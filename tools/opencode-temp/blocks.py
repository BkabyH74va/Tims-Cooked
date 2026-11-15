import sys, json
sys.path.insert(0, r'G:/REPO\tools\opencode-temp')
import fdiff2
qa, qb = fdiff2.run(r'G:/REPO\analysis\agx\2701.disasm.txt', r'G:/REPO\tools\opencode-temp\starts2701.txt',
                    r'G:/REPO\analysis\agx\272.disasm.txt', r'G:/REPO\tools\opencode-temp\starts272.txt')
import difflib
ha=[h for _,_,h in qa]; hb=[h for _,_,h in qb]
sm=difflib.SequenceMatcher(a=ha,b=hb,autojunk=False)
blocks=[]
for tag,a0,a1,b0,b1 in sm.get_opcodes():
    if tag in ('replace','insert','delete'):
        blocks.append((tag,a1-a0,b1-b0))
print('blocks',len(blocks))
from collections import Counter
print(Counter((min(a,20),min(b,20)) for t,a,b in blocks).most_common(20))
print('max',max(blocks,key=lambda x:x[1]+x[2]))
print('sum replace A',sum(a for t,a,b in blocks if t=='replace'),'B',sum(b for t,a,b in blocks if t=='replace'))
