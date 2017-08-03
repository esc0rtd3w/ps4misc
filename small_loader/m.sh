nasm -f bin source/pl.asm -o build/pl
python -c "f = open('build/pl').read();print([ord(a) for a in f])"
