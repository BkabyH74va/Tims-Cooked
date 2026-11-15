import sys
sys.path.insert(0, '.')
f = open('/tmp/worse_query/worse_query/ContentView.swift', 'r')
content = f.read()
f.close()
content = content.replace('@State private var path = "/private/var/mobile/Containers/Shared/AppGroup/"', '@State private var path = "/"')
old_on_appear = ".onAppear() {\n                console.start()\n            }"
new_on_appear = ".onAppear() {\n                console.start()\n                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {\n                    sandboxHandle = consumeExtension(path)\n                }\n            }"
content = content.replace(old_on_appear, new_on_appear)
f = open('/tmp/worse_query/worse_query/ContentView.swift', 'w')
f.write(content)
f.close()
print('done')
