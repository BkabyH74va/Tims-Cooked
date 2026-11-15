svm = 0xfffffe0007a18790
fs  = 0x72b0
vm  = 0xfffffe0007a1906be
print("in range:", svm <= vm < svm + fs)
print("end:", hex(svm + fs))
print("diff:", hex(vm - svm))