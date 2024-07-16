#!/bin/sh

set -e

FUZZDIR=${1?}

mkdir -p ${FUZZDIR}

if [ -r "/proc/sys/kernel/core_pattern" ]; then
    line=$(head -n 1 /proc/sys/kernel/core_pattern)
    if [ "$line" != "core" ]; then
	echo "unexpected core pattern $line"
	exit 1
    fi
fi

prepare()
{
    ARG_TYPE=$1

    mkdir -p ${FUZZDIR}/${ARG_TYPE}/input
    ./unit_${ARG_TYPE} dump ${FUZZDIR}/${ARG_TYPE}/input
    afl-cmin -i ${FUZZDIR}/${ARG_TYPE}/input -o ${FUZZDIR}/${ARG_TYPE}/testcases -- ./fuzz_${ARG_TYPE} @@
}

fuzz_tmux()
{
    ARG_TYPE=$1
    ARG_WINDOW=$2

    tmux set-window-option -t ${ARG_WINDOW} remain-on-exit on
    tmux send-keys -t ${ARG_WINDOW} "AFL_TMPDIR=${FUZZDIR}/${ARG_TYPE} AFL_SKIP_CPUFREQ=1 afl-fuzz -i ${FUZZDIR}/${ARG_TYPE}/testcases -o ${FUZZDIR}/${ARG_TYPE}/findings -- ./fuzz_${ARG_TYPE} @@" C-m
}

prepare cmd_dealias
prepare cmd_host
prepare cmd_http
prepare cmd_ping
prepare cmd_sniff
prepare cmd_sting
prepare cmd_tbit
prepare cmd_trace
prepare cmd_udpprobe
prepare host_rr_list

tmux new-session -d -s fuzz-scamper
tmux rename-window -t fuzz-scamper:0 'fuzz-cmd-dealias'
fuzz_tmux cmd_dealias fuzz-scamper:0

tmux new-window -t fuzz-scamper:1 -n 'fuzz-cmd-host'
fuzz_tmux cmd_host fuzz-scamper:1

tmux new-window -t fuzz-scamper:2 -n 'fuzz-cmd-http'
fuzz_tmux cmd_http fuzz-scamper:2

tmux new-window -t fuzz-scamper:3 -n 'fuzz-cmd-ping'
fuzz_tmux cmd_ping fuzz-scamper:3

tmux new-window -t fuzz-scamper:4 -n 'fuzz-cmd-sniff'
fuzz_tmux cmd_sniff fuzz-scamper:4

tmux new-window -t fuzz-scamper:5 -n 'fuzz-cmd-sting'
fuzz_tmux cmd_sting fuzz-scamper:5

tmux new-window -t fuzz-scamper:6 -n 'fuzz-cmd-tbit'
fuzz_tmux cmd_tbit fuzz-scamper:6

tmux new-window -t fuzz-scamper:7 -n 'fuzz-cmd-trace'
fuzz_tmux cmd_trace fuzz-scamper:7

tmux new-window -t fuzz-scamper:8 -n 'fuzz-cmd-udpprobe'
fuzz_tmux cmd_udpprobe fuzz-scamper:8

tmux new-window -t fuzz-scamper:9 -n 'fuzz-host-rr-list'
fuzz_tmux host_rr_list fuzz-scamper:9
