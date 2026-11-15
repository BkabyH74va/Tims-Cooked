#include <metal_stdlib>
using namespace metal;

// Read one uint32 from a device buffer at a BYTE offset (the offset is
// deliberately allowed to run past the buffer's declared length: that is the
// whole point of the F1 probe - the IOSurface's GPU mapping is sized from the
// surface geometry, so the hardware address space beyond the 64 KiB backing
// store is still mapped).
kernel void readU32(device uint32_t* buf      [[buffer(0)]],
                    constant uint32_t& offset  [[buffer(1)]],
                    device uint32_t& result   [[buffer(2)]])
{
    result[0] = buf[offset >> 2];
}

// Write one uint32 at a BYTE offset.
kernel void writeU32(device uint32_t* buf     [[buffer(0)]],
                     constant uint32_t& offset [[buffer(1)]],
                     constant uint32_t& value  [[buffer(2)]])
{
    buf[offset >> 2] = value;
}
