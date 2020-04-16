#!/bin/bash
#
# Simple wrapper script for creating flamegraphs from a pstack collection
#
# Jeff Rybczynski
# jrybczynski@splunk.com
# September 2019
#

version="0.0.1"
debug_enabled="true"
stacks_dir=""
output_fg=""
interactive=0

function get_params() {
	echo -n "Enter input pstacks directory full path: "
	read stacks_dir
	echo -n "Enter output stacks/flamegraph name: "
	read output_fg
}

function debug() {
	if [[ "$debug_enabled" == 'true' ]]; then
		echo $1
	fi
}

function print_usage() {
	echo "usage: $0 [-Viq] [-s|--stacks <PSTACKS DIRECTORY>] [-o|--output OUTPUT NAME] "
	echo "  Either -i or [-s|--stacks <PSTACKS DIRECTORY>] and "
	echo "               [-o|--output OUTPUT NAME] are required"
	echo ""
	echo "  -s|--stacks <PSTACKSDIR>  Set input pstacks directory"
	echo "  -o|--output <OUTPUTNAME> Set output name for flamegraph"
	echo "  -i|--interactive         Interactive mode will prompt user for stacks and output dir"
	echo "  -V|--version             Prints script version (as if it's really needed....)"
	echo "  -q|--quiet               Quiet mode supresses output messages"
	echo "  -h|--help                Prints this lovely message"
	exit
}

function cleanup_existing() {
	# Cleanup existing directories if they exist
	# But ask first....
	if [[ "$interactive" == '1' ]] && [[ -d $output_fg ]]; then
		echo "Cleanup previous files"
		echo "Remove $output_fg directory? (y/n)"
		read ans
		if [[ "$ans" == 'y' ]]; then
			rm -rf $output_fg
		fi
		rm -i $output_fg.tar.gz
		rm -i $output_fg.svg
	fi
}

function check_collisions() {
	# Check if output_fg direcotry or file exists already and add a 
	# trailing number if so
	if [[ -d "$output_fg" ]] || [[ -f "$output_fg" ]]; then
		count=1
		temp_name=$( echo $output_fg"_"$count)
		debug "Check if this output exists: $temp_name"
		while [[ -d "$temp_name" ]] || [[ -f "$temp_name" ]]; do
			count=$((count+1))
			temp_name=$( echo $output_fg"_"$count)
			debug "Change name to: $temp_name and check"
		done
		output_fg=$temp_name
	fi
	debug "First open output: $output_fg"
}

# Get command line options
while [[ "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
  -V | --version )
    echo "Version: $version" 
    exit
    ;;
  -h | --help )
    print_usage;
    ;;
  -s | --stacks )
    shift; stacks_dir=$1
    ;;
  -o | --output )
    shift; output_fg=$1
    ;;
  -i | --interactive )
    interactive=1
    ;;
  -q | --quiet )
    debug_enabled='false'
    ;;
esac; shift; done
if [[ "$1" == '--' ]]; then shift; fi


# Run interactive mode if needed
if [[ "$interactive" == '1' ]]; then 
	get_params;
fi 

# Make sure we got everything we need
rel_path=`dirname $0`
working_dir=`pwd`
export SPLUNK_HOME=$rel_dir
run_fixup=$( echo $rel_path"/"bin/fixup_stacks.py)
run_getstacks=$( echo $rel_path"/bin/getstacks.py")
if [[ -z "$output_fg" ]] || [[ -z "$stacks_dir" ]]; then
	debug "Got -o $output_fg and -s $stacks_dir"
	print_usage;
fi

# Cleanup past runs
cleanup_existing;

# Check for collisions
check_collisions;

# Create fixup stacks folder
if [[ "$output_fg" = /* ]]; then
	debug "Output: $output_fg is a full path"
else
	debug "Output: $output_fg is a relative path.  Append $working_dir"
	output_fg=$working_dir/$output_fg
fi
debug "Making fixup folder $output_fg"
mkdir $output_fg

# Run fixup on stacks
debug "Fixing up stacks in $stacks_dir and moving to $output_fg/"
if ls $stacks_dir/stack*.out 1> /dev/null 2>&1; then
	debug "Pstack collection filename format stack*.out exists"
	eval $run_fixup " --file $stacks_dir/stack*.out --outputDir $output_fg"
fi
if ls $stacks_dir/pstack*.out 1> /dev/null 2>&1; then
	debug "Pstack collection filename format pstack*.out exists"
	eval $run_fixup " --file $stacks_dir/pstack*.out --outputDir $output_fg"
fi


# Create fixup tarball
debug "Creating fixup tarball at $output_fg.tar.gz"
tar_opts="-czf"
if [[ "$debug_enabled" == 'true' ]]; then
	tar_opts="-vczf"
fi
tar $tar_opts $output_fg.tar.gz -C $output_fg/ .
if [[ ! -f "$output_fg.tar.gz" ]]; then
	echo "No $output_fg.tar.gz file to create flamegraph.  Bail."
	exit
fi

# Run getstacks and create flamegraph
debug "Run getstacks to create flamegraph"
eval $run_getstacks " -F $output_fg.tar.gz > $output_fg.svg"
echo "Flamegraph available at $output_fg.svg"
