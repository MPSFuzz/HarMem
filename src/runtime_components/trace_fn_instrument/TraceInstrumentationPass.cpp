#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/ADT/DenseMap.h"

#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace llvm;

namespace {
struct FuncMeta {
  unsigned Id;
  std::string Name;
  std::string Filename;
  unsigned Line;
};

struct BranchMeta {
  unsigned Id;
  unsigned FuncId;
  std::string Filename;
  unsigned Line;
};

struct CallMeta {
  unsigned Id;
  unsigned FromFuncId;
  unsigned ToFuncId;
  std::string CalleeName;
  std::string Filename;
  unsigned Line;
};

struct MarkerMeta {
  uint32_t Id;
  unsigned FuncId;      // function local id
  std::string Filename; // absolute file path
  unsigned Line;
  std::string Tag; // marker tag, e.g., "bug_point"
};

class TraceInstrumentationPass
    : public PassInfoMixin<TraceInstrumentationPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

private:
  void assignFunctionIds(Module &M, DenseMap<Function *, unsigned> &FuncIdMap,
                         std::vector<FuncMeta> &FuncMetas);

  void instrumentModule(Module &M, uint32_t ModuleId,
                        DenseMap<Function *, unsigned> &FuncIdMap,
                        std::vector<FuncMeta> &FuncMetas,
                        std::vector<BranchMeta> &BranchMetas,
                        std::vector<CallMeta> &CallMetas,
                        std::vector<MarkerMeta> &MarkerMetas);

  void writeMetaJson(const Module &M, uint32_t ModuleId,
                     const std::vector<FuncMeta> &FuncMetas,
                     const std::vector<BranchMeta> &BranchMetas,
                     const std::vector<CallMeta> &CallMetas,
                     const std::vector<MarkerMeta> &MarkerMetas);

  static std::string escapeJsonString(const std::string &S);
};
} // namespace

// support functions for escaping JSON strings
std::string TraceInstrumentationPass::escapeJsonString(const std::string &S) {
  std::string Out;
  Out.reserve(S.size() +
              8); // Reserve some extra space to avoid multiple allocations
  for (char c : S) {
    switch (c) {
    case '\\':
      Out += "\\\\";
      break;
    case '"':
      Out += "\\\"";
      break;
    case '\n':
      Out += "\\n";
      break;
    case '\r':
      Out += "\\r";
      break;
    case '\t':
      Out += "\\t";
      break;
    default:
      Out += c;
      break;
    }
  }

  return Out;
}

// support function to get absolute file path and line number from instruction
static void getAbsoluteFileAndLine(const Instruction &I, std::string &OutFile,
                                   unsigned &OutLine) {
  OutFile.clear();
  OutLine = 0;

  if (const DILocation *Loc = I.getDebugLoc()) {
    const DIFile *F = Loc->getFile();
    StringRef Filename;
    StringRef Directory;

    if (F) {
      Filename = F->getFilename();
      Directory = F->getDirectory();
    } else {
      Filename = Loc->getFilename();
      Directory = Loc->getDirectory();
    }

    SmallString<256> FullPath;
    if (!Directory.empty())
      sys::path::append(FullPath, Directory, Filename);
    else
      FullPath = Filename;

    SmallString<256> Real;
    if (!FullPath.empty() && !sys::fs::real_path(FullPath, Real))
      OutFile = Real.str().str();
    else
      OutFile = FullPath.str().str();

    OutLine = Loc->getLine();
  }
}

// support function to get absolute file path and line number from Function
static void getFuncFileAndLine(Function &F, std::string &OutFile,
                               unsigned &OutLine) {
  OutFile.clear();
  OutLine = 0;
  for (auto &BB : F) {
    for (auto &I : BB) {
      if (I.getDebugLoc()) {
        getAbsoluteFileAndLine(I, OutFile, OutLine);
        if (!OutFile.empty())
          return;
      }
    }
  }
}

// stable hash function for module path to generate module ID
static uint32_t stableModuleId(StringRef Path) {
  uint32_t h = 2166136261u;
  for (unsigned char c : Path) {
    h ^= c;
    h *= 16777619u;
  }
  return h;
}

struct TargetLoc {
  std::string FileAbsOrRaw;
  std::string BaseName;
  unsigned Line;
  uint32_t MarkerId;
};

static inline std::string trim(const std::string &s) {
  size_t b = 0, e = s.size();
  while (b < e && isspace((unsigned char)s[b]))
    b++;
  while (e > b && isspace((unsigned char)s[e - 1]))
    e--;
  return s.substr(b, e - b);
}

static bool parseOneTargetLine(
    const std::string &line, std::string &outFile,
    unsigned
        &outLine) { // handle target information in file, format: <file>:<line>
  std::string t = trim(line);
  if (t.empty())
    return false;

  size_t pos = t.rfind(':');
  if (pos == std::string::npos)
    return false;

  outFile = trim(t.substr(0, pos));
  std::string sLine = trim(t.substr(pos + 1));
  if (outFile.empty() || sLine.empty())
    return false;

  char *endp = nullptr;
  long v = std::strtol(sLine.c_str(), &endp, 10);
  if (!endp || *endp != '\0' || v <= 0)
    return false;

  outLine = (unsigned)v;
  return true;
}

static std::vector<TargetLoc> loadTargetsFromFile(const char *pathEnv) {
  std::vector<TargetLoc> out;
  if (!pathEnv || !*pathEnv)
    return out;

  std::ifstream fin(pathEnv);
  if (!fin.is_open())
    return out;

  std::string line;
  while (std::getline(fin, line)) {
    std::string file;
    unsigned ln = 0;
    if (!parseOneTargetLine(line, file, ln))
      continue;

    // normalize path to real_path if possible
    std::string real = file;
    SmallString<256> RealPath;
    if (!file.empty() && !sys::fs::real_path(file, RealPath)) {
      real = RealPath.str().str();
    }

    // basename for fallback match
    SmallString<256> base(file);
    sys::path::remove_dots(base, true);
    std::string bn = sys::path::filename(StringRef(base)).str();

    std::string idStr = real + ":" + std::to_string(ln);
    uint32_t mid = stableModuleId(idStr);

    TargetLoc tloc;
    tloc.FileAbsOrRaw = real;
    tloc.BaseName = bn;
    tloc.Line = ln;
    tloc.MarkerId = mid;
    out.push_back(std::move(tloc));
  }

  return out;
}

void TraceInstrumentationPass::assignFunctionIds(
    Module &M, DenseMap<Function *, unsigned> &FuncIdMap,
    std::vector<FuncMeta> &FuncMetas) {
  unsigned NextId = 0;
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    unsigned Id = NextId++;
    FuncIdMap[&F] = Id;

    std::string Filename;
    unsigned Line;
    getFuncFileAndLine(F, Filename, Line);

    // for (auto &BB : F) {
    //   for (auto &I : BB) {
    //     if (DILocation *Loc = I.getDebugLoc()) {
    //       Filename = Loc->getFilename().str();
    //       Line = Loc->getLine();
    //       break;
    //     }
    //   }
    //   if (!Filename.empty())
    //     break;
    // }

    FuncMeta FM;
    FM.Id = Id;
    FM.Name = F.getName().str();
    FM.Filename = Filename;
    FM.Line = Line;
    FuncMetas.push_back(std::move(FM));
  }
}

void TraceInstrumentationPass::instrumentModule(
    Module &M, uint32_t ModuleId, DenseMap<Function *, unsigned> &FuncIdMap,
    std::vector<FuncMeta> &FuncMetas, std::vector<BranchMeta> &BranchMetas,
    std::vector<CallMeta> &CallMetas, std::vector<MarkerMeta> &MarkerMetas) {
  LLVMContext &ctx = M.getContext();
  Type *VoidTy = Type::getVoidTy(ctx);
  Type *Int1Ty = Type::getInt1Ty(ctx);
  Type *Int32Ty = Type::getInt32Ty(ctx);

  // Declare runtime functions
  FunctionCallee EnterFunc = M.getOrInsertFunction(
      "trace_fn_enter", FunctionType::get(VoidTy, {Int32Ty, Int32Ty}, false));
  FunctionCallee ExitFunc = M.getOrInsertFunction(
      "trace_fn_exit", FunctionType::get(VoidTy, {Int32Ty, Int32Ty}, false));
  FunctionCallee BranchFunc = M.getOrInsertFunction(
      "trace_branch",
      FunctionType::get(VoidTy, {Int32Ty, Int32Ty, Int32Ty, Int1Ty}, false));
  FunctionCallee CallEdgeFunc = M.getOrInsertFunction(
      "trace_call_edge",
      FunctionType::get(VoidTy, {Int32Ty, Int32Ty, Int32Ty, Int32Ty}, false));
  FunctionCallee MarkerFunc = M.getOrInsertFunction(
      "trace_marker",
      FunctionType::get(VoidTy, {Int32Ty, Int32Ty, Int32Ty}, false));

  const char *targetPath = std::getenv("TRACE_MARKER_TARGETS_FILE");
  std::vector<TargetLoc> targets = loadTargetsFromFile(targetPath);

  // Build a quick lookup:
  // - key by absolute path, and by basename fallback
  std::unordered_map<std::string, std::unordered_set<unsigned>> file2lines;
  std::unordered_map<std::string, std::unordered_set<unsigned>> base2lines;
  std::unordered_map<std::string, std::unordered_map<unsigned, uint32_t>>
      fileLine2Marker;
  std::unordered_map<std::string, std::unordered_map<unsigned, uint32_t>>
      baseLine2Marker;

  for (auto &t : targets) {
    file2lines[t.FileAbsOrRaw].insert(t.Line);
    base2lines[t.BaseName].insert(t.Line);
    fileLine2Marker[t.FileAbsOrRaw][t.Line] = t.MarkerId;
    baseLine2Marker[t.BaseName][t.Line] = t.MarkerId;
  }

  unsigned NextBrachId = 0;
  unsigned NextCallId = 0;

  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    auto FuncIdIt = FuncIdMap.find(&F);
    if (FuncIdIt == FuncIdMap.end())
      continue;
    unsigned FuncId = FuncIdIt->second;

    ConstantInt *ModuleIdVal =
        cast<ConstantInt>(ConstantInt::get(Int32Ty, ModuleId));

    ConstantInt *FuncIdVal =
        static_cast<ConstantInt *>(ConstantInt::get(Int32Ty, FuncId));

    // Instrument function entry
    IRBuilder<> EntryBuilder(&*F.getEntryBlock().getFirstInsertionPt());
    EntryBuilder.CreateCall(EnterFunc, {ModuleIdVal, FuncIdVal});

    // Instrument function returns
    SmallVector<ReturnInst *, 8> Returns;
    for (auto &BB : F) {
      if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        Returns.push_back(RI);
      }
    }

    for (ReturnInst *RI : Returns) {
      IRBuilder<> RetBuilder(RI);
      RetBuilder.CreateCall(ExitFunc, {ModuleIdVal, FuncIdVal});
    }

    // To avoid duplicating marker insertion multiple times in the same
    // function/line, we keep a set of inserted marker ids for this function.
    DenseSet<uint32_t> insertedMarkerIdsInFunc;

    // Instrument branches and calls
    for (auto &BB : F) {
      Instruction *Term = BB.getTerminator();

      if (auto *BI = dyn_cast<BranchInst>(Term)) {
        if (BI->isConditional()) {
          unsigned BranchId = NextBrachId++;
          ConstantInt *BranchIdVal =
              static_cast<ConstantInt *>(ConstantInt::get(Int32Ty, BranchId));
          Value *Cond = BI->getCondition();

          // record branch meta
          std::string Filename;
          unsigned Line;
          getAbsoluteFileAndLine(*BI, Filename, Line);

          BranchMeta BM;
          BM.Id = BranchId;
          BM.FuncId = FuncId;
          BM.Filename = Filename;
          BM.Line = Line;
          BranchMetas.push_back(std::move(BM));

          IRBuilder<> BranchBuilder(BI);
          BranchBuilder.CreateCall(BranchFunc,
                                   {ModuleIdVal, FuncIdVal, BranchIdVal, Cond});
        }
      }

      if (!targets.empty()) {
        for (auto &I : BB) {
          std::string Filename;
          unsigned Line = 0;
          getAbsoluteFileAndLine(I, Filename, Line);
          if (Filename.empty() || Line == 0)
            continue;

          std::string base = sys::path::filename(StringRef(Filename)).str();

          bool hit = false;
          uint32_t markerId = 0;

          auto itf = file2lines.find(Filename);
          if (itf != file2lines.end() && itf->second.count(Line)) {
            hit = true;
            markerId = fileLine2Marker[Filename][Line];
          } else {
            auto itb = base2lines.find(base);
            if (itb != base2lines.end() && itb->second.count(Line)) {
              hit = true;
              markerId = baseLine2Marker[base][Line];
            }
          }

          if (!hit)
            continue;

          if (insertedMarkerIdsInFunc.contains(markerId))
            continue; // already inserted in this function

          insertedMarkerIdsInFunc.insert(markerId);

          ConstantInt *MarkerIdVal =
              static_cast<ConstantInt *>(ConstantInt::get(Int32Ty, markerId));

          IRBuilder<> MarkerBuilder(&I);
          MarkerBuilder.CreateCall(MarkerFunc,
                                   {ModuleIdVal, FuncIdVal, MarkerIdVal});

          // record marker meta (tag as bug_point by default)
          MarkerMeta MM;
          MM.Id = markerId;
          MM.FuncId = FuncId;
          MM.Filename = Filename;
          MM.Line = Line;
          MM.Tag = "bug_point";
          MarkerMetas.push_back(std::move(MM));
        }
      }

      // instrument calls
      for (auto &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB)
          continue;

        Function *Callee = CB->getCalledFunction();
        if (!Callee)
          continue; // ignore indirect calls

        auto ToIt = FuncIdMap.find(Callee);
        if (ToIt == FuncIdMap.end())
          continue; // callee not in our map

        unsigned ToFuncId = ToIt->second;
        unsigned CallId = NextCallId++;

        ConstantInt *CallIdVal =
            static_cast<ConstantInt *>(ConstantInt::get(Int32Ty, CallId));
        ConstantInt *ToFuncIdVal =
            static_cast<ConstantInt *>(ConstantInt::get(Int32Ty, ToFuncId));

        // record call meta
        std::string Filename;
        unsigned Line;
        getAbsoluteFileAndLine(*CB, Filename, Line);

        CallMeta CM;
        CM.Id = CallId;
        CM.FromFuncId = FuncId;
        CM.ToFuncId = ToFuncId;
        CM.CalleeName = Callee->getName().str();
        CM.Filename = Filename;
        CM.Line = Line;
        CallMetas.push_back(std::move(CM));

        IRBuilder<> CallBuilder(CB);
        CallBuilder.CreateCall(
            CallEdgeFunc, {ModuleIdVal, FuncIdVal, ToFuncIdVal, CallIdVal});
      }
    }
  }
}

void TraceInstrumentationPass::writeMetaJson(
    const Module &M, uint32_t ModuleId, const std::vector<FuncMeta> &FuncMetas,
    const std::vector<BranchMeta> &BranchMetas,
    const std::vector<CallMeta> &CallMetas,
    const std::vector<MarkerMeta> &MarkerMetas) {

  using namespace llvm;
  using namespace llvm::sys;
  std::string SrcName = M.getSourceFileName().c_str();
  if (SrcName.empty()) {
    SrcName = "unknown_module";
  }

  StringRef SrcRef(SrcName);
  SmallString<128> Base = path::filename(SrcRef);
  std::string ModuleName = Base.str().str();

  SmallString<128> JsonBase = Base;
  path::replace_extension(JsonBase, ".json");

  SmallString<128> OutPath("/tmp/trace_meta_");
  OutPath += JsonBase;
  std::error_code EC;
  raw_fd_ostream OS(OutPath, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "[TraceInstrumentationPass] Failed to open " << OutPath << ": "
           << EC.message() << "\n";
    return;
  }

  //   std::string ModuleName = Base.str().str();

  OS << "{\n";
  OS << "  \"module\": \"" << escapeJsonString(ModuleName) << "\",\n";
  OS << "  \"module_id\": " << ModuleId << ",\n";

  // ---- functions ----
  OS << "  \"functions\": [\n";
  for (size_t i = 0; i < FuncMetas.size(); ++i) {
    const auto &F = FuncMetas[i];
    OS << "    {\"id\": " << F.Id << ", \"name\": \""
       << escapeJsonString(F.Name) << "\""
       << ", \"file\": \"" << escapeJsonString(F.Filename) << "\""
       << ", \"line\": " << F.Line << "}";
    if (i + 1 != FuncMetas.size())
      OS << ",";
    OS << "\n";
  }
  OS << "  ],\n";

  // ---- branches ----
  OS << "  \"branches\": [\n";
  for (size_t i = 0; i < BranchMetas.size(); ++i) {
    const auto &B = BranchMetas[i];
    OS << "    {\"id\": " << B.Id << ", \"func_id\": " << B.FuncId
       << ", \"file\": \"" << escapeJsonString(B.Filename) << "\""
       << ", \"line\": " << B.Line << "}";
    if (i + 1 != BranchMetas.size())
      OS << ",";
    OS << "\n";
  }
  OS << "  ],\n";

  // ---- calls ----
  OS << "  \"calls\": [\n";
  for (size_t i = 0; i < CallMetas.size(); ++i) {
    const auto &C = CallMetas[i];
    OS << "    {\"id\": " << C.Id << ", \"from_func_id\": " << C.FromFuncId
       << ", \"to_func_id\": " << C.ToFuncId << ", \"callee\": \""
       << escapeJsonString(C.CalleeName) << "\""
       << ", \"file\": \"" << escapeJsonString(C.Filename) << "\""
       << ", \"line\": " << C.Line << "}";
    if (i + 1 != CallMetas.size())
      OS << ",";
    OS << "\n";
  }
  OS << "  ],\n";
  // markers trace information
  OS << "  \"markers\": [\n";
  for (size_t i = 0; i < MarkerMetas.size(); ++i) {
    const auto &MK = MarkerMetas[i];
    OS << "    {\"id\": " << MK.Id << ", \"func_id\": " << MK.FuncId
       << ", \"tag\": \"" << escapeJsonString(MK.Tag) << "\""
       << ", \"file\": \"" << escapeJsonString(MK.Filename) << "\""
       << ", \"line\": " << MK.Line << "}";
    if (i + 1 != MarkerMetas.size())
      OS << ",";
    OS << "\n";
  }
  OS << "  ]\n";
  OS << "}\n";
}

// Main pass entry point run()
PreservedAnalyses TraceInstrumentationPass::run(Module &M,
                                                ModuleAnalysisManager &MAM) {
  DenseMap<Function *, unsigned> FuncIdMap;
  std::vector<FuncMeta> FuncMetas;
  std::vector<BranchMeta> BranchMetas;
  std::vector<CallMeta> CallMetas;
  std::vector<MarkerMeta> MarkerMetas;

  std::string ModPath = M.getSourceFileName().c_str();
  uint32_t ModuleId = stableModuleId(ModPath);

  assignFunctionIds(M, FuncIdMap, FuncMetas);
  instrumentModule(M, ModuleId, FuncIdMap, FuncMetas, BranchMetas, CallMetas,
                   MarkerMetas);

  // Write metadata JSON
  writeMetaJson(M, ModuleId, FuncMetas, BranchMetas, CallMetas, MarkerMetas);

  return PreservedAnalyses::none();
}

// Pass registration
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "TraceInstrumentationPass", "1.0",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "trace-instrumentation") {
                    MPM.addPass(TraceInstrumentationPass());
                    return true;
                  }
                  return false;
                });
            // mount on the optimization pipeline in clang
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, llvm::OptimizationLevel Level,
                   llvm::ThinOrFullLTOPhase Phase) {
                  MPM.addPass(TraceInstrumentationPass());
                });
          }};
}

// clang++ -fPIC -shared TraceInstrumentationPass.cpp -o TraceInstrumentationPass.so \
//  $(llvm-config --cxxflags) \
//  $(llvm-config --ldflags) \
//  $(llvm-config --system-libs) \
//  $(llvm-config --libs --link-shared)