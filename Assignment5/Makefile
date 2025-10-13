all: client tsamgroup21

client: client.cpp
	g++ -o client client.cpp

tsamgroup21: tsamgroup21.cpp
	g++ -std=c++11 -pthread -o tsamgroup21 tsamgroup21.cpp

clean:
	rm -f client tsamgroup21

.PHONY: all clean
