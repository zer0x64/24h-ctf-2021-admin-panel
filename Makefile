build_dir = build

all: $(build_dir)/admin_panel

$(build_dir)/admin_panel: $(build_dir)/stager_debug $(build_dir)
	strip $(build_dir)/stager_debug -o $(build_dir)/admin_panel
	execstack -c $(build_dir)/admin_panel

$(build_dir)/stager_debug: $(build_dir)/stager.o $(build_dir)
	gcc -no-pie $(build_dir)/stager.o -o $(build_dir)/stager_debug

$(build_dir)/stager.o: $(build_dir)/stager_temp.s $(build_dir)
	nasm $(build_dir)/stager_temp.s -f elf64 -o $(build_dir)/stager.o

$(build_dir)/stager_temp.s: stager.s core_dumper.py $(build_dir)/core.bin $(build_dir)
	python3 core_dumper.py $(build_dir)

$(build_dir)/core.bin: core.s $(build_dir)
	nasm core.s -o $(build_dir)/core.bin

$(build_dir):
	mkdir $(build_dir)

clean:
	rm $(build_dir)/*
