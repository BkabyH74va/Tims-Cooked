svm = 0xfffffe0007a18790
vm  = 0xfffffe0007a1906be
print(len("fffffe0007a18790"), len("fffffe0007a1906be"))
print(repr(hex(svm)))
print(repr(hex(vm)))
print(svm < vm)