all: protected
evo:
	g++ -Wall -Werror -o evo main.cpp
protected: protected.c
	gcc -Wall -Werror -o protected protected.c
