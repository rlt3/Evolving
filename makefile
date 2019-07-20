all:
	g++ -Wall -Werror -o evo main.cpp
test: protected encrypt
protected: protected.c
	gcc -Wall -Werror -o protected protected.c
encrypt: encrypt.c
	gcc -Wall -Werror -o encrypt encrypt.c
