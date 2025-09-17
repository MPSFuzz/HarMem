/*
   aflgo - LLVM instrumentation pass
   ---------------------------------

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_LLVM_PASS

#include "/aflgo/afl-2.57b/config.h" // MAP_SIZE / banner macros if needed
#include "/aflgo/afl-2.57b/debug.h" // SAYF/OKF/WARNF/FATAL (optional, can be removed)

#include <cstdlib>
#include <fstream>
#include <list>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
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
// #include "llvm/IR/Dominators.h" // If you ever need DT in the future
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/GraphWriter.h" // WriteGraph
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

// ===== Flags (compatible with original pass) =================================

static cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file (csv) with 'filename:line,distance' entries."),
    cl::value_desc("filename"));

static cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc(
        "Input file containing the target lines (filename:line per line)."),
    cl::value_desc("targets"));

static cl::opt<std::string>
    OutDirectory("outdir",
                 cl::desc("Output dir for BBnames.txt, BBcalls.txt, "
                          "Fnames.txt, Ftargets.txt, and dot-files."),
                 cl::value_desc("outdir"));

// ===== Constants & helpers ===================================================

#ifndef MAP_SIZE
#define MAP_SIZE (1 << 16)
#endif

// Avoid name clash with AFL's AFL_R(x) macro:
static inline uint32_t afl_rand(RandomNumberGenerator &RNG, uint32_t limit) {
  if (limit == 0)
    return 0;
  // RandomNumberGenerator::operator()
  uint64_t r = RNG();
  return static_cast<uint32_t>(r % limit);
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
      "asan.", "llvm.",  "sancov.", "__ubsan_handle_",
      "free",  "malloc", "calloc",  "realloc"};
  for (auto const &P : Blacklist)
    if (F->getName().starts_with(P))
      return true; // LLVM21: starts_with
  return false;
}

static void getDebugLocModern(const Instruction *I, std::string &Filename,
                              unsigned &Line) {
  Filename.clear();
  Line = 0;
  if (const DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    if (auto F = Loc->getFilename(); !F.empty())
      Filename = std::string(F);
    else if (const DILocation *Inl = Loc->getInlinedAt()) {
      Line = Inl->getLine();
      Filename = std::string(Inl->getFilename());
    }
  }
  if (!Filename.empty()) {
    size_t p = Filename.find_last_of("/\\");
    if (p != std::string::npos)
      Filename = Filename.substr(p + 1);
  }
}

static inline std::string standardizeBBkey(BasicBlock &BB) {
  for (Instruction &I : BB) {
    std::string filename;
    unsigned line = 0;
    getDebugLocModern(&I, filename, line);
    if (!filename.empty() && line != 0) {
      return filename + ":" + std::to_string(line);
    }
  }

  return "";
}

// Optional: nicer node labels for CFG dump (by BB name)
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

// ===== The Pass ==============================================================

namespace {
class AFLGoPass : public PassInfoMixin<AFLGoPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
    const bool Tty = isatty(2);
    const bool BeQuiet = !(Tty && !std::getenv("AFL_QUIET"));

    if (!TargetsFile.empty() && !DistanceFile.empty()) {
      WithColor::error() << "Cannot use both '-targets' and '-distance'.\n";
      return PreservedAnalyses::all();
    }

    // Ratios & flags from env (compatible with AFLGo)
    unsigned inst_ratio = 100;
    if (const char *p = std::getenv("AFL_INST_RATIO")) {
      unsigned v = 0;
      if (sscanf(p, "%u", &v) != 1 || v == 0 || v > 100) {
        WithColor::error() << "Bad AFL_INST_RATIO (1..100).\n";
        return PreservedAnalyses::all();
      }
      inst_ratio = v;
    }
    unsigned is_selective = 0;
    if (const char *p = std::getenv("AFLGO_SELECTIVE")) {
      unsigned v = 0;
      if (sscanf(p, "%u", &v) != 1) {
        WithColor::error() << "Bad AFLGO_SELECTIVE (0 or 1).\n";
        return PreservedAnalyses::all();
      }
      is_selective = v;
    }
    unsigned dinst_ratio = 100;
    if (const char *p = std::getenv("AFLGO_INST_RATIO")) {
      unsigned v = 0;
      if (sscanf(p, "%u", &v) != 1 || v == 0 || v > 100) {
        WithColor::error() << "Bad AFLGO_INST_RATIO (1..100).\n";
        return PreservedAnalyses::all();
      }
      dinst_ratio = v;
    }

    const bool is_pre = !TargetsFile.empty();
    const bool is_dist = !DistanceFile.empty();

    std::unique_ptr<RandomNumberGenerator> RNG = M.createRNG("aflgo-pass");

    // ===================== Preprocessing mode ================================
    if (is_pre) {
      if (OutDirectory.empty()) {
        WithColor::error() << "Provide '-outdir <dir>' for preprocessing.\n";
        return PreservedAnalyses::all();
      }

      std::list<std::string> targets;
      {
        std::ifstream fin(TargetsFile);
        if (!fin) {
          WithColor::error()
              << "Cannot open targets file: " << TargetsFile << "\n";
          return PreservedAnalyses::all();
        }
        std::string line;
        while (std::getline(fin, line))
          targets.push_back(line);
      }

      std::string dotdir = OutDirectory + "/dot-files";
      if (std::error_code ec = sys::fs::create_directories(dotdir)) {
        WithColor::error() << "Could not create directory: " << dotdir << " ("
                           << ec.message() << ")\n";
        return PreservedAnalyses::all();
      }

      std::ofstream bbnames(OutDirectory + "/BBnames.txt",
                            std::ofstream::out | std::ofstream::trunc);
      std::ofstream bbcalls(OutDirectory + "/BBcalls.txt",
                            std::ofstream::out | std::ofstream::trunc);
      std::ofstream fnames(OutDirectory + "/Fnames.txt",
                           std::ofstream::out | std::ofstream::trunc);
      std::ofstream ftargets(OutDirectory + "/Ftargets.txt",
                             std::ofstream::out | std::ofstream::trunc);

      for (Function &F : M) {
        if (F.isDeclaration() || isBlacklisted(&F))
          continue;

        bool has_BBs = false;
        bool is_target_func = false;

        for (BasicBlock &BB : F) {
          std::string bb_name;

          for (Instruction &I : BB) {
            std::string filename;
            unsigned line = 0;
            getDebugLocModern(&I, filename, line);
            if (filename.empty() || line == 0)
              continue;

            if (bb_name.empty())
              bb_name = filename + ":" + std::to_string(line);

            if (!is_target_func) {
              for (auto t : targets) {
                size_t p = t.find_last_of("/\\");
                if (p != std::string::npos)
                  t = t.substr(p + 1);
                size_t c = t.find_last_of(":");
                if (c == std::string::npos)
                  continue;
                std::string tf = t.substr(0, c);
                unsigned tl = (unsigned)atoi(t.substr(c + 1).c_str());
                if (tf == filename && tl == line) {
                  is_target_func = true;
                  break;
                }
              }
            }

            if (auto *CI = dyn_cast<CallInst>(&I)) {
              if (Function *Callee = CI->getCalledFunction()) {
                // if (!isBlacklisted(Callee) && !bb_name.empty()) {
                //   bbcalls << bb_name << "," << Callee->getName().str() <<
                //   "\n";
                // }
                if (!isBlacklisted(Callee)) {
                  std::string key = standardizeBBkey(BB);
                  if (!key.empty())
                    bbcalls << key << "," << Callee->getName().str() << "\n";
                }
              }
            }
          }

          // if (!bb_name.empty()) {
          //   BB.setName(bb_name + ":");
          //   bbnames << BB.getName().str() << "\n";
          //   has_BBs = true;
          // }
          {
            std::string key = standardizeBBkey(BB);
            if (!key.empty()) {
              BB.setName(key + ":");
              // BB.setName(key);
              bbnames << key << "\n";
              has_BBs = true;
            }
          }
        }

        if (has_BBs) {
          std::string cfgFileName =
              dotdir + "/cfg." + std::string(F.getName()) + ".dot";
          std::error_code EC;
          raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::OF_None);
          if (!EC) {
            WriteGraph(cfgFile, &F, /*ShortNames*/ true);
          }
          if (is_target_func)
            ftargets << F.getName().str() << "\n";
          fnames << F.getName().str() << "\n";
        }
      }

      if (!BeQuiet)
        WithColor::note() << "aflgo-llvm-pass preprocessing finished.\n";
      return PreservedAnalyses::none();
    }

    // ===================== Distance mode / vanilla mode ======================
    std::map<std::string, int> bb_to_dis;
    std::vector<std::string> basic_blocks;

    if (is_dist) {
      std::ifstream cf(DistanceFile);
      if (!cf) {
        WithColor::error() << "Unable to open distance file: " << DistanceFile
                           << "\n";
        return PreservedAnalyses::all();
      }
      std::string line;
      while (std::getline(cf, line)) {
        size_t pos = line.find(",");
        if (pos == std::string::npos)
          continue;
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int)(100.0 * atof(line.substr(pos + 1).c_str()));
        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);
      }
      if (!BeQuiet)
        WithColor::note() << "Loaded " << bb_to_dis.size()
                          << " distance entries.\n";
    } else {
      if (!BeQuiet)
        WithColor::note() << "Running non-AFLGo instrumentation.\n";
    }

    // Types and globals
    LLVMContext &C = M.getContext();
    IntegerType *I8 = IntegerType::getInt8Ty(C);
    IntegerType *I32 = IntegerType::getInt32Ty(C);
    IntegerType *I64 = IntegerType::getInt64Ty(C);

#if defined(__x86_64__) || defined(_M_X64)
    IntegerType *Largest = I64;
    ConstantInt *MapCntLoc = ConstantInt::get(Largest, MAP_SIZE + 8);
#else
    IntegerType *Largest = I32;
    ConstantInt *MapCntLoc = ConstantInt::get(Largest, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(Largest, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(Largest, 1);

    // LLVM 21: prefer explicit pointer type construction
    auto *I8Ptr = PointerType::get(IntegerType::getInt8Ty(C), 0);

    auto *AFLMapPtr = new GlobalVariable(
        M, I8Ptr, /*isConstant*/ false, GlobalValue::ExternalLinkage,
        /*Initializer*/ nullptr, "__afl_area_ptr");

    auto *AFLPrevLoc = new GlobalVariable(
        M, I32, /*isConstant*/ false, GlobalValue::ExternalLinkage,
        /*Initializer*/ nullptr, "__afl_prev_loc",
        /*InsertBefore*/ nullptr, GlobalVariable::GeneralDynamicTLSModel);

    int inst_blocks = 0;

    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      for (BasicBlock &BB : F) {
        if (afl_rand(*RNG, 100) >= inst_ratio)
          continue;

        // Compute distance if in distance mode
        int distance = -1;
        if (is_dist) {
          std::string bb_name;
          for (Instruction &I : BB) {
            std::string filename;
            unsigned line = 0;
            getDebugLocModern(&I, filename, line);
            if (!filename.empty() && line != 0) {
              bb_name = filename + ":" + std::to_string(line);
              break;
            }
          }
          if (!bb_name.empty()) {
            bool in_list = (std::find(basic_blocks.begin(), basic_blocks.end(),
                                      bb_name) != basic_blocks.end());
            if (!in_list) {
              if (is_selective)
                continue; // skip if selective and not in list
            } else {
              if (afl_rand(*RNG, 100) < dinst_ratio) {
                auto it = bb_to_dis.find(bb_name);
                if (it != bb_to_dis.end())
                  distance = it->second;
              }
            }
          }
        }

        // Instrument at BB entry
        IRBuilder<> IRB(&*BB.getFirstInsertionPt());

        // cur_loc
        uint32_t cur_loc = afl_rand(*RNG, MAP_SIZE);
        ConstantInt *CurLoc = ConstantInt::get(I32, cur_loc);

        // prev_loc = load
        LoadInst *PrevLoc = IRB.CreateLoad(I32, AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
        Value *PrevLocZext = IRB.CreateZExt(PrevLoc, I32);

        // shm ptr
        LoadInst *MapPtr = IRB.CreateLoad(I8Ptr, AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        // idx = prev ^ cur
        Value *Idx = IRB.CreateXor(PrevLocZext, CurLoc);

        // map[idx]
        Value *MapPtrIdx = IRB.CreateGEP(I8, MapPtr, Idx);

        // counter++
        LoadInst *Counter = IRB.CreateLoad(I8, MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
        Value *Incr8 = IRB.CreateAdd(Counter, ConstantInt::get(I8, 1));
        StoreInst *StCtr = IRB.CreateStore(Incr8, MapPtrIdx);
        StCtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        // prev_loc = cur_loc >> 1
        StoreInst *StPrev =
            IRB.CreateStore(ConstantInt::get(I32, cur_loc >> 1), AFLPrevLoc);
        StPrev->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

        // Optional distance accumulation at tail of shm
        if (distance >= 0) {
          ConstantInt *Dist = ConstantInt::get(Largest, (unsigned)distance);

          // *(Largest*)(map + MAP_SIZE) += Dist
          Value *MapDistBytePtr = IRB.CreateGEP(I8, MapPtr, MapDistLoc);
          Value *MapDistPtr =
              IRB.CreateBitCast(MapDistBytePtr, Largest->getPointerTo());

          LoadInst *MapDistVal = IRB.CreateLoad(Largest, MapDistPtr);
          MapDistVal->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, {}));
          Value *IncDist = IRB.CreateAdd(MapDistVal, Dist);
          StoreInst *StDist = IRB.CreateStore(IncDist, MapDistPtr);
          StDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));

          // *(Largest*)(map + MAP_SIZE + sizeof(Largest)) += 1
          Value *MapCntBytePtr = IRB.CreateGEP(I8, MapPtr, MapCntLoc);
          Value *MapCntPtr =
              IRB.CreateBitCast(MapCntBytePtr, Largest->getPointerTo());

          LoadInst *MapCntVal = IRB.CreateLoad(Largest, MapCntPtr);
          MapCntVal->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, {}));
          Value *IncCnt = IRB.CreateAdd(MapCntVal, One);
          StoreInst *StCnt = IRB.CreateStore(IncCnt, MapCntPtr);
          StCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, {}));
        }

        ++inst_blocks;
      }
    }

    if (!is_pre && !BeQuiet) {
      if (!inst_blocks)
        WithColor::warning() << "No instrumentation targets found.\n";
      else
        WithColor::note() << "Instrumented " << inst_blocks
                          << " locations (ratio " << inst_ratio
                          << "%, dist. ratio " << dinst_ratio << "%).\n";
    }

    return PreservedAnalyses::none();
  }
};
} // namespace

// ===== Plugin registration ===================================================

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AFLGoPass", "0.3-llvm21",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "aflgo-npm") {
                    MPM.addPass(AFLGoPass());
                    return true;
                  }
                  return false;
                });

            // If you want auto-insertion into default pipelines, uncomment:
            // PB.registerPipelineStartEPCallback(
            //     [](ModulePassManager &MPM, PassBuilder::OptimizationLevel) {
            //       MPM.addPass(AFLGoPass());
            //     });
          }};
}
