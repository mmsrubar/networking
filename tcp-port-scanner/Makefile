FILE=tcp-port-scanner

all: $(FILE)

$(FILE): $(FILE).c
	gcc -Wall -Wextra -pedantic $< -o $@

clean:
	rm $(FILE)
