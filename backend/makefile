

LIBS= `pkg-config --libs raftlib`
# LIBS= -L/usr/local/lib -lraft -lpthread -lshm -lrt -lnuma -laffinity -lpthread -ldemangle -lcmdargs

# --unused libs--
# -lcmph -lpcap 

CFLAGS = `pkg-config --cflags raftlib` -O2 -fopt-info-vec-optimized -funroll-loops
# CFLAGS = `pkg-config --cflags raftlib` 
# CFLAGS = -L/usr/local/lib -lraft -lpthread -lshm -lrt -lnuma -laffinity -lpthread -ldemangle -lcmdargs -Ofast -fopt-info-vec-optimized -funroll-loops

# --unused flags (some from other projects) --
# CFLAGS = -std=c++14 -Ofast -fopt-info-vec-optimized
# -std=c++14 -O3 -funroll-loops -mprefer-vector-width=512 -march=skylake-avx512 -fopt-info-vec-optimized #-mavx512f -mavx512dq -mavx512bw -mavx512vbmi -mavx512vbmi2 -mavx512vl

CC = g++

objects = benchmark_main
all: $(objects)

$(objects): %: src/%.cpp	
	$(CC) -o $@ $< $(LIBS) $(CFLAGS)

clean: 
	rm  $(objects)