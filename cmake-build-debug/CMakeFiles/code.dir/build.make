# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.8

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/code.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/code.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/code.dir/flags.make

CMakeFiles/code.dir/buffer.c.o: CMakeFiles/code.dir/flags.make
CMakeFiles/code.dir/buffer.c.o: ../buffer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/code.dir/buffer.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/code.dir/buffer.c.o   -c /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/buffer.c

CMakeFiles/code.dir/buffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/code.dir/buffer.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/buffer.c > CMakeFiles/code.dir/buffer.c.i

CMakeFiles/code.dir/buffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/code.dir/buffer.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/buffer.c -o CMakeFiles/code.dir/buffer.c.s

CMakeFiles/code.dir/buffer.c.o.requires:

.PHONY : CMakeFiles/code.dir/buffer.c.o.requires

CMakeFiles/code.dir/buffer.c.o.provides: CMakeFiles/code.dir/buffer.c.o.requires
	$(MAKE) -f CMakeFiles/code.dir/build.make CMakeFiles/code.dir/buffer.c.o.provides.build
.PHONY : CMakeFiles/code.dir/buffer.c.o.provides

CMakeFiles/code.dir/buffer.c.o.provides.build: CMakeFiles/code.dir/buffer.c.o


CMakeFiles/code.dir/reliable.c.o: CMakeFiles/code.dir/flags.make
CMakeFiles/code.dir/reliable.c.o: ../reliable.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/code.dir/reliable.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/code.dir/reliable.c.o   -c /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable.c

CMakeFiles/code.dir/reliable.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/code.dir/reliable.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable.c > CMakeFiles/code.dir/reliable.c.i

CMakeFiles/code.dir/reliable.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/code.dir/reliable.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable.c -o CMakeFiles/code.dir/reliable.c.s

CMakeFiles/code.dir/reliable.c.o.requires:

.PHONY : CMakeFiles/code.dir/reliable.c.o.requires

CMakeFiles/code.dir/reliable.c.o.provides: CMakeFiles/code.dir/reliable.c.o.requires
	$(MAKE) -f CMakeFiles/code.dir/build.make CMakeFiles/code.dir/reliable.c.o.provides.build
.PHONY : CMakeFiles/code.dir/reliable.c.o.provides

CMakeFiles/code.dir/reliable.c.o.provides.build: CMakeFiles/code.dir/reliable.c.o


CMakeFiles/code.dir/reliable_blank_skeleton.c.o: CMakeFiles/code.dir/flags.make
CMakeFiles/code.dir/reliable_blank_skeleton.c.o: ../reliable_blank_skeleton.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/code.dir/reliable_blank_skeleton.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/code.dir/reliable_blank_skeleton.c.o   -c /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable_blank_skeleton.c

CMakeFiles/code.dir/reliable_blank_skeleton.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/code.dir/reliable_blank_skeleton.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable_blank_skeleton.c > CMakeFiles/code.dir/reliable_blank_skeleton.c.i

CMakeFiles/code.dir/reliable_blank_skeleton.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/code.dir/reliable_blank_skeleton.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/reliable_blank_skeleton.c -o CMakeFiles/code.dir/reliable_blank_skeleton.c.s

CMakeFiles/code.dir/reliable_blank_skeleton.c.o.requires:

.PHONY : CMakeFiles/code.dir/reliable_blank_skeleton.c.o.requires

CMakeFiles/code.dir/reliable_blank_skeleton.c.o.provides: CMakeFiles/code.dir/reliable_blank_skeleton.c.o.requires
	$(MAKE) -f CMakeFiles/code.dir/build.make CMakeFiles/code.dir/reliable_blank_skeleton.c.o.provides.build
.PHONY : CMakeFiles/code.dir/reliable_blank_skeleton.c.o.provides

CMakeFiles/code.dir/reliable_blank_skeleton.c.o.provides.build: CMakeFiles/code.dir/reliable_blank_skeleton.c.o


CMakeFiles/code.dir/rlib.c.o: CMakeFiles/code.dir/flags.make
CMakeFiles/code.dir/rlib.c.o: ../rlib.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/code.dir/rlib.c.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/code.dir/rlib.c.o   -c /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/rlib.c

CMakeFiles/code.dir/rlib.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/code.dir/rlib.c.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/rlib.c > CMakeFiles/code.dir/rlib.c.i

CMakeFiles/code.dir/rlib.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/code.dir/rlib.c.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/rlib.c -o CMakeFiles/code.dir/rlib.c.s

CMakeFiles/code.dir/rlib.c.o.requires:

.PHONY : CMakeFiles/code.dir/rlib.c.o.requires

CMakeFiles/code.dir/rlib.c.o.provides: CMakeFiles/code.dir/rlib.c.o.requires
	$(MAKE) -f CMakeFiles/code.dir/build.make CMakeFiles/code.dir/rlib.c.o.provides.build
.PHONY : CMakeFiles/code.dir/rlib.c.o.provides

CMakeFiles/code.dir/rlib.c.o.provides.build: CMakeFiles/code.dir/rlib.c.o


# Object files for target code
code_OBJECTS = \
"CMakeFiles/code.dir/buffer.c.o" \
"CMakeFiles/code.dir/reliable.c.o" \
"CMakeFiles/code.dir/reliable_blank_skeleton.c.o" \
"CMakeFiles/code.dir/rlib.c.o"

# External object files for target code
code_EXTERNAL_OBJECTS =

code: CMakeFiles/code.dir/buffer.c.o
code: CMakeFiles/code.dir/reliable.c.o
code: CMakeFiles/code.dir/reliable_blank_skeleton.c.o
code: CMakeFiles/code.dir/rlib.c.o
code: CMakeFiles/code.dir/build.make
code: CMakeFiles/code.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking C executable code"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/code.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/code.dir/build: code

.PHONY : CMakeFiles/code.dir/build

CMakeFiles/code.dir/requires: CMakeFiles/code.dir/buffer.c.o.requires
CMakeFiles/code.dir/requires: CMakeFiles/code.dir/reliable.c.o.requires
CMakeFiles/code.dir/requires: CMakeFiles/code.dir/reliable_blank_skeleton.c.o.requires
CMakeFiles/code.dir/requires: CMakeFiles/code.dir/rlib.c.o.requires

.PHONY : CMakeFiles/code.dir/requires

CMakeFiles/code.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/code.dir/cmake_clean.cmake
.PHONY : CMakeFiles/code.dir/clean

CMakeFiles/code.dir/depend:
	cd /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug /Users/Adi/Documents/Code/Studium/Networks/project-1-reliable/code/cmake-build-debug/CMakeFiles/code.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/code.dir/depend
