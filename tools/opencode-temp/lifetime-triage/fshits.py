lines = open("/tmp/fs.txt", "rb").read().decode("utf-8", "replace").splitlines()
out = []
for i, l in enumerate(lines):
    if "0xfffffe000903" in l:
        out.append(f"{i}: {l}")
with open("/tmp/fshits_out.txt", "w") as fh:
    fh.write("\n".join(out))
with open("/tmp/fshits_n.txt", "w") as fh:
    fh.write(str(len(out)))
