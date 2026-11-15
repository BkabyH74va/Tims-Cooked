package main

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func main() {
	image := `G:/REPO\iPhone18,1_27.2_24B119_Restore\141-08824-244.dmg`
	outPath := `G:/REPO\analysis\ios\dsc_27_272\dyld_shared_cache_arm64e`

	container, closer, err := apfs.OpenImage(image, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer closer.Close()
	defer container.Close()

	vol, err := container.VolumeBySelector("0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "volume:", err)
		os.Exit(1)
	}

	fmt.Println("volume open: ok")
	fmt.Println("btree:", vol.FileSystemBTree)
	rootNode, err := vol.FileSystemBTree.RootNode(vol.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "root node:", err)
		os.Exit(1)
	}
	fmt.Println("root node header: flags=", rootNode.NodeHeader.Flags, "level=", rootNode.NodeHeader.Level, "keys=", rootNode.NodeHeader.NumberOfKeys)
	fmt.Println("root node info: flags=", rootNode.Info.Flags, "nodeSize=", rootNode.Info.NodeSize, "keySize=", rootNode.Info.KeySize, "valueSize=", rootNode.Info.ValueSize, "maxKeySize=", rootNode.Info.MaximumKeySize, "maxValueSize=", rootNode.Info.MaximumValueSize, "totalKeys=", rootNode.Info.TotalNumberOfKeys, "totalNodes=", rootNode.Info.TotalNumberOfNodes)
	for i, e := range rootNode.Entries {
		fmt.Println("entry", i, "keyLen=", len(e.KeyData), "valueLen=", len(e.ValueData), "key=", fmt.Sprintf("%x", e.KeyData), "value=", fmt.Sprintf("%x", e.ValueData))
	}

	data, err := fs.ReadFile(vol, "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}

	fmt.Println("wrote", len(data), "bytes")
}
