// aflgo-pass-npm.cpp
/*
   aflgo - LLVM instrumentation pass (NPM version, preserving original features)
   ---------------------------------------------------------------------------------------

   This file adapts your original legacy ModulePass into an NPM Module pass
   while preserving functionality:

   - Preprocessing mode (-targets & -outdir): writes BBnames/Fnames/Ftargets and
   cfg dot files
   - Distance instrumentation mode (-distance): AFL coverage + distance
   accumulation
   - Ensures OutDirectory/dot-files creation
   - Pre-parse targets into map<filename,set<line>>
   - If no debug info for a BB, generate fallback key (funcname:bb_index)
   - Check ofstream open status and FATAL on failure
   - Flush per-function and close files at end of preprocessing
   - Use AFL logging macros (SAYF/OKF/WARNF/FATAL) and LLVM errs()/WithColor
   when needed
*/

#define AFL_LLVM_PASS

#include "/aflgo/afl-2.57b/config.h"
#include "/aflgo/afl-2.57b/debug.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/GraphWriter.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

#define DEBUG_TYPE "aflgo-npm"

using namespace llvm;

/* -------------------------- CLI options -------------------------- */

cl::opt<std::string>
    DistanceFile("distance",
                 cl::desc("Distance file containing the distance of each basic "
                          "block to the provided targets."),
                 cl::value_desc("filename"));

cl::opt<std::string>
    TargetsFile("targets",
                cl::desc("Input file containing the target lines of code."),
                cl::value_desc("targets"));

cl::opt<std::string>
    OutDirectory("outdir",
                 cl::desc("Output directory where Ftargets.txt, Fnames.txt, "
                          "and BBnames.txt are generated."),
                 cl::value_desc("outdir"));

/* ---------------- DOT graph traits for Function* (CFG dump) ----------------
 */

namespace llvm {

template <> struct DOTGraphTraits<Function *> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple = true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function * /*Graph*/) {
    if (!Node->getName().empty())
      return Node->getName().str();
    std::string Str;
    raw_string_ostream OS(Str);
    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

/* -------------------------- helpers -------------------------- */

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#if defined(LLVM_OLD_DEBUG_API)
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    // NOTE: This branch is kept for very old LLVM builds. It may require
    // additional compatibility tweaks if you actually define
    // LLVM_OLD_DEBUG_API.
    DILocation cDILoc(Loc.getAsMDNode(I->getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();
    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();
    if (Filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (const DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();
    if (Filename.empty()) {
      if (const DILocation *oDILoc = Loc->getInlinedAt()) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif
}

static bool isBlacklisted(const Function *F) {
  static const char *Blacklist[] = {"asan.",           "llvm.",  "sancov.",
                                    "__ubsan_handle_", "free",   "malloc",
                                    "calloc",          "realloc"};
  StringRef Name = F->getName();
  for (const char *Prefix : Blacklist) {
    if (Name.starts_with(Prefix))
      return true;
  }
  return false;
}

/* -------------------------- NPM Pass -------------------------- */

struct AFLGoPass : public PassInfoMixin<AFLGoPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

PreservedAnalyses AFLGoPass::run(Module &M, ModuleAnalysisManager & /*AM*/) {

  bool Changed = false;
  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (TargetsFile.empty() && DistanceFile.empty()) {
    if (const char *d = std::getenv("AFLGO_DISTANCE"))
      DistanceFile = d;
    if (const char *t = std::getenv("AFLGO_TARGETS"))
      TargetsFile = t;
  }
  if (OutDirectory.empty()) {
    if (const char *o = std::getenv("AFLGO_OUTDIR"))
      OutDirectory = o;
  }

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return PreservedAnalyses::none();
  }

  std::list<std::string> targets;
  std::map<std::string, int> bb_to_dis;
  std::vector<std::string> basic_blocks;

  if (!TargetsFile.empty()) {
    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return PreservedAnalyses::none();
    }

    std::ifstream targetsfile(TargetsFile);
    if (!targetsfile.is_open()) {
      FATAL("Unable to open targets file: %s", TargetsFile.c_str());
      return PreservedAnalyses::none();
    }
    std::string line;
    while (std::getline(targetsfile, line))
      targets.push_back(line);
    targetsfile.close();
    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {
    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {
      std::string line;
      while (std::getline(cf, line)) {
        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);

        if (!bb_name.empty() && bb_name.back() == ':')
          bb_name.pop_back();

        int bb_dis = (int)(100.0 * atof(line.substr(pos + 1).c_str()));
        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);
      }
      cf.close();
      is_aflgo = true;
    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return PreservedAnalyses::none();
    }
  }

  /* Banner */
  char be_quiet = 0;
  if (isatty(2) && !getenv("AFL_QUIET")) {
    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing"
                                   : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST
                " by <lszekeres@google.com>\n");
  } else
    be_quiet = 1;

  /* Instrumentation ratio */
  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Selective mode */
  char *is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;
  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  /* Distance inst ratio */
  char *dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;
  if (dinst_ratio_str) {
    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");
  }

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {
    /* ========= Preprocessing mode ========= */

    SmallString<256> OutAbs(OutDirectory);
    if (std::error_code E = sys::fs::make_absolute(OutAbs)) {
      FATAL("make_absolute failed for outdir=%s", OutDirectory.c_str());
      return PreservedAnalyses::none();
    }
    std::string OutDirAbs =
        std::string(OutAbs.str()); // 不再依赖 remove_leading_dotslash

    std::error_code EC_bn, EC_bc, EC_fn, EC_ft;
    raw_fd_ostream bbnames(OutDirAbs + "/BBnames.txt", EC_bn,
                           sys::fs::OF_Append);
    raw_fd_ostream bbcalls(OutDirAbs + "/BBcalls.txt", EC_bc,
                           sys::fs::OF_Append);
    raw_fd_ostream fnames(OutDirAbs + "/Fnames.txt", EC_fn, sys::fs::OF_Append);
    raw_fd_ostream ftargets(OutDirAbs + "/Ftargets.txt", EC_ft,
                            sys::fs::OF_Append);
    if (EC_bn || EC_bc || EC_fn || EC_ft) {
      FATAL("open outputs failed: %s%s%s%s",
            EC_bn ? (" BBnames:" + EC_bn.message()).c_str() : "",
            EC_bc ? (" BBcalls:" + EC_bc.message()).c_str() : "",
            EC_fn ? (" Fnames:" + EC_fn.message()).c_str() : "",
            EC_ft ? (" Ftargets:" + EC_ft.message()).c_str() : "");
      return PreservedAnalyses::none();
    }

    std::string dotfiles = OutDirAbs + "/dot-files";
    if (std::error_code E = sys::fs::create_directory(dotfiles)) {
      if (E != std::errc::file_exists) {
        FATAL("Could not create directory %s: %s", dotfiles.c_str(),
              E.message().c_str());
        return PreservedAnalyses::none();
      }
    }

    std::map<std::string, std::set<unsigned>> TargetsIndex;
    for (const auto &t_raw : targets) {
      if (t_raw.empty())
        continue;
      std::string t = t_raw;
      size_t pos = t.find_last_of(':');
      if (pos == std::string::npos)
        continue;
      std::string file = t.substr(0, pos);
      unsigned line = (unsigned)atoi(t.substr(pos + 1).c_str());
      size_t slash = file.find_last_of("/\\");
      if (slash != std::string::npos)
        file = file.substr(slash + 1);
      TargetsIndex[file].insert(line);
    }

    auto matchesAnyTarget = [&](const Instruction &I) -> bool {
      if (const DILocation *Loc = I.getDebugLoc()) {
        for (const DILocation *L = Loc; L; L = L->getInlinedAt()) {
          std::string fname = L->getFilename().str();
          unsigned line = L->getLine();
          if (fname.empty() || line == 0)
            continue;
          size_t p = fname.find_last_of("/\\");
          if (p != std::string::npos)
            fname = fname.substr(p + 1);
          auto it = TargetsIndex.find(fname);
          if (it != TargetsIndex.end() && it->second.count(line))
            return true;
        }
      }
      return false;
    };

    auto getOrigSubprogramName = [&](const Instruction &I) -> std::string {
      if (const DILocation *Loc = I.getDebugLoc()) {
        for (const DILocation *L = Loc; L; L = L->getInlinedAt()) {
          if (const auto *SP = dyn_cast_or_null<DISubprogram>(L->getScope()))
            return SP->getName().str();
        }
      }
      return {};
    };

    size_t FnVisited = 0, FnWithBBs = 0, BBTotal = 0, CallsTotal = 0;

    for (auto &F : M) {
      ++FnVisited;

      if (isBlacklisted(&F))
        continue;

      bool has_BBs = false;
      bool is_target_func = false;
      const std::string funcName = F.getName().str();

      std::set<const Function *> PreciseFuncs;

      unsigned bb_index = 0;
      for (auto &BB : F) {
        ++BBTotal;

        // ---- Step 1: 先确定 bb_name（优先 filename:line，缺失则
        // func:bb_idx）----
        std::string bb_name;
        {
          std::string filename;
          unsigned line = 0;
          static const std::string Xlibs("/usr/");
          for (auto &I : BB) {
            filename.clear();
            line = 0;
            getDebugLoc(&I, filename, line);
            if (filename.empty() || line == 0 ||
                !filename.compare(0, Xlibs.size(), Xlibs)) {
              continue;
            }
            size_t p = filename.find_last_of("/\\");
            if (p != std::string::npos)
              filename = filename.substr(p + 1);
            bb_name = filename + ":" + std::to_string(line);
            break; // 只取该 BB 的第一处分行号
          }
          if (bb_name.empty())
            bb_name = funcName + ":" + std::to_string(bb_index);
        }

        // ---- Step 2: 指令级命中 + 原始子程序归属（解决内联归属问题）----
        if (!is_target_func) {
          for (auto &I : BB) {
            if (matchesAnyTarget(I)) {
              is_target_func = true;
              if (std::string orig = getOrigSubprogramName(I); !orig.empty()) {
                if (Function *F2 = M.getFunction(orig)) {
                  PreciseFuncs.insert(F2); // 记录更精确的目标函数
                }
              }
              break; // 命中一条指令即可
            }
          }
        }

        // ---- Step 3: 记录调用（CallBase + stripPointerCasts，覆盖
        // bitcast/invoke）----
        for (auto &I : BB) {
          if (auto *CB = dyn_cast<CallBase>(&I)) {
            const Value *CalleeVal = CB->getCalledOperand();
            if (!CalleeVal)
              continue;
            CalleeVal = CalleeVal->stripPointerCasts();
            if (const Function *CalledF = dyn_cast<Function>(CalleeVal)) {
              if (!isBlacklisted(CalledF)) {
                bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
                ++CallsTotal;
              }
            }
          }
        }

        // ---- Step 4: 记录 BB 名 ----
        BB.setName(bb_name + ":");
        bbnames << BB.getName().str() << "\n";
        has_BBs = true;

#ifdef AFLGO_TRACING
        if (auto *TI = BB.getTerminator()) {
          IRBuilder<> Builder(TI);
          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {Type::getInt8PtrTy(M.getContext())};
          FunctionType *FTy =
              FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented =
              M.getOrInsertFunction("llvm_profiling_call", FTy).getCallee();
          Builder.CreateCall(FTy, instrumented, {bbnameVal});
        }
#endif

        ++bb_index;
      } // for BB

      if (has_BBs) {
        ++FnWithBBs;

        // dump CFG dot（绝对路径）
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code E2;
#if LLVM_VERSION_MAJOR >= 17
        raw_fd_ostream cfgFile(cfgFileName, E2, sys::fs::OF_None);
#else
        raw_fd_ostream cfgFile(cfgFileName, E2, sys::fs::F_None);
#endif
        if (!E2) {
          WriteGraph(cfgFile, &F, true);
          cfgFile.flush();
        }

        // 优先写“原始子程序”命中；否则回退到当前函数
        bool wrote = false;
        if (!PreciseFuncs.empty()) {
          for (const Function *TF : PreciseFuncs) {
            ftargets << TF->getName().str() << "\n";
            wrote = true;
          }
        }
        if (!wrote && is_target_func) {
          ftargets << F.getName().str() << "\n";
        }

        fnames << F.getName().str() << "\n";
      }

      // 每个函数末尾主动 flush 一次
      bbnames.flush();
      bbcalls.flush();
      fnames.flush();
      ftargets.flush();
    } // for Function

    OKF("[aflgo-preproc] outdir=%s funcs=%zu (with BBs=%zu) BBs=%zu calls=%zu",
        OutDirAbs.c_str(), FnVisited, FnWithBBs, BBTotal, CallsTotal);

    // 关闭在析构里自动完成
    Changed = true;
  } else {
    /* ========= Distance instrumentation mode ========= */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    // SHM globals
    auto *AFLMapPtr = new GlobalVariable(M, PointerType::get(C, 0), false,
                                         GlobalValue::ExternalLinkage, nullptr,
                                         "__afl_area_ptr");

    auto *AFLPrevLoc =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage,
                           nullptr, "__afl_prev_loc", nullptr,
                           GlobalVariable::GeneralDynamicTLSModel, 0, false);

    for (auto &F : M) {
      for (auto &BB : F) {
        int distance = -1;

        if (is_aflgo) {
          std::string bb_name;
          // prefer debuginfo
          for (auto &I : BB) {
            std::string filename;
            unsigned line = 0;
            getDebugLoc(&I, filename, line);
            if (filename.empty() || line == 0)
              continue;
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);
            bb_name =
                filename + ":" +
                std::to_string(line); // the format of bb_name:filename:line
            break;
          }
          // fallback if no debuginfo
          if (bb_name.empty()) {
            // compute BB index for fallback
            unsigned idx = 0;
            for (auto &BB2 : F) {
              if (&BB2 == &BB)
                break;
              ++idx;
            }
            bb_name = F.getName().str() + ":" +
                      std::to_string(idx); // extra operation: when getDebugLoc
                                           // fails, use funcname:bb_index
          }

          if (!bb_name.empty()) {
            if (find(basic_blocks.begin(), basic_blocks.end(),
                     bb_name) == // basic_blocks is from distance file, which
                                 // contains all BBs with distance values,
                                 // like:stream.c:1608:,6
                basic_blocks.end()) {
              if (is_selective)
                continue; // skip non-target when selective
            } else {
              if (AFL_R(100) < dinst_ratio) {
                auto it = bb_to_dis.find(
                    bb_name); // bb_to_dis is from distance
                              // file, map<bb_name,distance> (a container)
                if (it != bb_to_dis.end())
                  distance = it->second;
              }
            }
          }
        }

        auto IP = BB.getFirstInsertionPt();
        if (IP == BB.end())
          continue;
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio)
          continue;

        // cur_loc
        unsigned int cur_loc = AFL_R(MAP_SIZE);
        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        // prev_loc load
#if LLVM_VERSION_MAJOR >= 15
        LoadInst *PrevLoc = IRB.CreateLoad(Int32Ty, AFLPrevLoc);
#else
        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
#endif
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
        // Value *PrevLocCasted =
        //     IRB.CreateZExt(PrevLoc, IRB.getInt32Ty()); // this may be
        //     redundant

        // MapPtr load
#if LLVM_VERSION_MAJOR >= 15
        LoadInst *MapPtr =
            IRB.CreateLoad(PointerType::get(C, 0),
                           AFLMapPtr); // a pointer point to AFLMapPtr
#else
        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
#endif
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        // idx = prev ^ cur
        Value *Idx = IRB.CreateXor(
            PrevLoc,
            CurLoc); // generate the index of the current basic block

        // gep MapPtr[idx]
#if LLVM_VERSION_MAJOR >= 15
        Value *MapPtrIdx = IRB.CreateGEP(
            Int8Ty, MapPtr, Idx); // get the address of the index in the map
#else
        Value *MapPtrIdx = IRB.CreateGEP(MapPtr, Idx);
#endif

        // bitmap[prev^cur]++
#if LLVM_VERSION_MAJOR >= 15
        LoadInst *Counter = IRB.CreateLoad(Int8Ty, MapPtrIdx);
#else
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
#endif
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
#if LLVM_VERSION_MAJOR >= 15
        auto *StoreCnt = IRB.CreateStore(Incr, MapPtrIdx);
#else
        auto *StoreCnt = IRB.CreateStore(Incr, MapPtrIdx);
#endif
        StoreCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        // prev_loc = cur_loc >> 1
        auto *StorePrev = IRB.CreateStore(
            ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        StorePrev->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        if (distance >= 0) {
          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned)distance);

          // shm[MAP_SIZE] += distance, so the index = MAP_SIZE in shm is the
          // total distance
#if LLVM_VERSION_MAJOR >= 15
          Value *MapDistBytePtr = IRB.CreateGEP(Int8Ty, MapPtr, MapDistLoc);
#else
          Value *MapDistBytePtr = IRB.CreateGEP(MapPtr, MapDistLoc);
#endif
          // Value *MapDistPtr =
          //     IRB.CreateBitCast(MapDistBytePtr, LargestType->getPointerTo());
#if LLVM_VERSION_MAJOR >= 15
          LoadInst *MapDist = IRB.CreateLoad(
              LargestType, MapDistBytePtr); // the MapDist ponit to the current
                                            // distance value in shm[MAP_SIZE]
#else
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
#endif
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          auto *StoreDist = IRB.CreateStore(IncrDist, MapDistBytePtr);
          StoreDist->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, {}));

          // shm[MAP_SIZE + (4 or 8)]++
#if LLVM_VERSION_MAJOR >= 15
          Value *MapCntBytePtr = IRB.CreateGEP(Int8Ty, MapPtr, MapCntLoc);
#else
          Value *MapCntBytePtr = IRB.CreateGEP(MapPtr, MapCntLoc);
#endif
          // Value *MapCntPtr =
          //     IRB.CreateBitCast(MapCntBytePtr, LargestType->getPointerTo());
#if LLVM_VERSION_MAJOR >= 15
          LoadInst *MapCnt = IRB.CreateLoad(LargestType, MapCntBytePtr);
#else
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
#endif
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          auto *StoreCnt2 = IRB.CreateStore(IncrCnt, MapCntBytePtr);
          StoreCnt2->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, {}));

          // calculate the number of basic blocks that have distance information
        }

        inst_blocks++;
        Changed = true;
      } // for BB
    } // for F
  }

  if (!is_aflgo_preprocessing && !be_quiet) {
    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
          inst_blocks,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio, dinst_ratio);
  }

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

/* -------------------------- Plugin entry (NPM registration)
 * -------------------------- */

extern "C" PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AFLGoPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // only run when arg:"-passes=" is set
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "aflgo-npm") {
                    MPM.addPass(AFLGoPass());
                    return true;
                  }
                  return false;
                });
            // auto run when pipeline is built
            PB.registerPipelineStartEPCallback(
                [&](ModulePassManager &MPM, OptimizationLevel) {
                  const char *D = std::getenv("AFLGO_DISTANCE");
                  const char *T = std::getenv("AFLGO_TARGETS");
                  if (D || T)
                    MPM.addPass(AFLGoPass());
                });
          }};
}
