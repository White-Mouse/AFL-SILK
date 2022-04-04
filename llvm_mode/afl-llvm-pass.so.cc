/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.
*/

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fstream>
#include <queue>
#include <unordered_set>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Instruction.h"

using namespace llvm;

namespace
{

  class AFLCoverage : public ModulePass
  {

  public:
    static char ID;
    AFLCoverage() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;
  };

}

char AFLCoverage::ID = 0;

// Determine whether a BasicBlock is interesting
static inline bool
is_interesting(BasicBlock &BB)
{
  bool interesting = false;
  Instruction *termInst = dyn_cast<Instruction>(BB.getTerminator());

  switch (termInst->getOpcode())
  {
  case Instruction::Br:
  {
    interesting = true;
    break;
  }

  case Instruction::IndirectBr:
  {
    interesting = true;
    break;
  }
  default:
    interesting = false;
  }
  return interesting;
}

// Get the BasicBlock id
static inline unsigned int
get_block_id(BasicBlock &bb)
{
  unsigned int bbid = 0;
  MDNode *bb_node = nullptr;
  for (auto &ins : bb)
  {
    if ((bb_node = ins.getMetadata("afl_cur_loc")))
      break;
  }
  if (bb_node)
  {
    bbid = cast<ConstantInt>(cast<ValueAsMetadata>(bb_node->getOperand(0))->getValue())->getZExtValue();
  }
  return bbid;
}

// Get the edge id
static inline unsigned int
get_edge_id(BasicBlock &pre, BasicBlock &cur)
{
  unsigned int pre_id = 0, cur_id = 0;
  pre_id = get_block_id(pre);
  cur_id = get_block_id(cur);
  if (pre_id && cur_id)
  {
    return ((pre_id >> 1) ^ cur_id);
  }
  return 0;
}

// Get the number of interesting successors
static inline int
num_suc_interesting(BasicBlock &bb)
{
  std::unordered_set<BasicBlock *> reachable;
  std::queue<BasicBlock *> worklist;
  int num = 0;
  BasicBlock *b = &bb;
  worklist.push(b);
  while (!worklist.empty())
  {
    BasicBlock *front = worklist.front();
    worklist.pop();
    for (BasicBlock *succ : successors(front))
    {
      if (reachable.count(succ) == 0)
      {
        if (is_interesting(*succ))
          num++;
        worklist.push(succ);
        reachable.insert(succ);
      }
    }
  }
  return num;
}

static inline bool
starts_with(const std::string &str, const std::string &prefix)
{
  if (prefix.length() > str.length())
  {
    return false;
  }
  return str.substr(0, prefix.length()) == prefix;
}

static inline bool
is_llvm_dbg_intrinsic(Instruction &instr)
{
  const bool is_call = instr.getOpcode() == Instruction::Invoke ||
                       instr.getOpcode() == Instruction::Call;
  if (!is_call)
  {
    return false;
  }

  CallSite cs(&instr);
  Function *calledFunc = cs.getCalledFunction();

  if (calledFunc != NULL)
  {
    const bool ret = calledFunc->isIntrinsic() &&
                     starts_with(calledFunc->getName().str(), "llvm.");
    return ret;
  }
  else
  {
    return false;
  }
}

bool AFLCoverage::runOnModule(Module &M)
{
  std::ofstream branchMap("branchMap.out", std::ofstream::out);
  std::ofstream edgeScore("edgeScore.out", std::ofstream::out);

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET"))
  {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");
  }
  else
    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str)
  {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");
  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F)
    {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio)
        continue;

      /* Make up cur_loc */

      unsigned int cur_loc = AFL_R(MAP_SIZE);

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      // Insert the metadata
      auto meta_loc = MDNode::get(C, ConstantAsMetadata::get(CurLoc));
      for (Instruction &instr : BB.getInstList())
      {
        if (!is_llvm_dbg_intrinsic(instr))
        {
          // this only insert the meta for the first non-llvm dbg
          instr.setMetadata("afl_cur_loc", meta_loc);
          break;
        }
      }

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      Value *Xor = IRB.CreateXor(PrevLocCasted, CurLoc);

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, Xor);

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;
    }

  /* Say something nice. */

  if (!be_quiet)
  {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else
      OKF("Instrumented %u locations (%s mode, ratio %u%%).",
          inst_blocks, getenv("AFL_HARDEN") ? "hardened" : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ? "ASAN/MSAN" : "non-hardened"), inst_ratio);
  }

  for (auto &F : M)
  {
    for (auto &BB : F)
    {
      Instruction *termInst = dyn_cast<Instruction>(BB.getTerminator());
      switch (termInst->getOpcode())
      {
      case Instruction::Br:
      {
        BranchInst &br_instr = cast<BranchInst>(*termInst);
        if (br_instr.isConditional())
        {
          for (unsigned int i = 0; i < br_instr.getNumSuccessors(); ++i)
          {
            if (i == 0)
              branchMap << get_block_id(BB) << "\t";
            auto dst_bb = br_instr.getSuccessor(i);
            unsigned int pair_edge = get_edge_id(BB, *dst_bb);
            if (pair_edge != 0)
            {
              branchMap << pair_edge << "\t";
              edgeScore << pair_edge << "\t";
              edgeScore << num_suc_interesting(BB) << "\n";
            }
          }
          branchMap << "\n";
        }
        break;
      }
      case Instruction::IndirectBr:
      {
        IndirectBrInst &ind_br_instr = cast<IndirectBrInst>(*termInst);
        for (unsigned int i = 0; i < ind_br_instr.getNumSuccessors(); ++i)
        {
          if (i == 0)
            branchMap << get_block_id(BB) << "\t";
          auto dst_bb = ind_br_instr.getSuccessor(i);
          unsigned int pair_edge = get_edge_id(BB, *dst_bb);
          if (pair_edge != 0)
          {
            branchMap << pair_edge << "\t";
            edgeScore << pair_edge << "\t";
            edgeScore << num_suc_interesting(BB) << "\n";
          }
        }
        branchMap << "\n";
        break;
      }
      }
    }
  }

  edgeScore.close();
  branchMap.close();

  return true;
}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM)
{

  PM.add(new AFLCoverage());
}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
