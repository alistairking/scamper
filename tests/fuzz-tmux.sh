#!/bin/sh

set -e

FUZZDIR=${1?}

mkdir -p ${FUZZDIR}

prepare()
{
    ARG_TYPE=$1

    mkdir -p ${FUZZDIR}/cmd_${ARG_TYPE}/input
    ./unit_cmd_${ARG_TYPE} dump ${FUZZDIR}/cmd_${ARG_TYPE}/input
    afl-cmin -i ${FUZZDIR}/cmd_${ARG_TYPE}/input -o ${FUZZDIR}/cmd_${ARG_TYPE}/testcases -- ./fuzz_cmd_${ARG_TYPE} @@
}

fuzz_tmux()
{
    ARG_TYPE=$1
    ARG_WINDOW=$2

    tmux set-window-option -t ${ARG_WINDOW} remain-on-exit on
    tmux send-keys -t ${ARG_WINDOW} "AFL_TMPDIR=${FUZZDIR}/cmd_${ARG_TYPE} AFL_SKIP_CPUFREQ=1 afl-fuzz -i ${FUZZDIR}/cmd_${ARG_TYPE}/testcases -o ${FUZZDIR}/cmd_${ARG_TYPE}/findings -- ./fuzz_cmd_${ARG_TYPE} @@" C-m
}

prepare dealias
prepare host
prepare http
prepare ping
prepare sniff
prepare sting
prepare tbit
prepare trace
prepare udpprobe

tmux new-session -d -s fuzz-cmd
tmux rename-window -t fuzz-cmd:0 'fuzz-cmd-dealias'
fuzz_tmux dealias fuzz-cmd:0

tmux new-window -t fuzz-cmd:1 -n 'fuzz-cmd-host'
fuzz_tmux host fuzz-cmd:1

tmux new-window -t fuzz-cmd:2 -n 'fuzz-cmd-http'
fuzz_tmux http fuzz-cmd:2

tmux new-window -t fuzz-cmd:3 -n 'fuzz-cmd-ping'
fuzz_tmux ping fuzz-cmd:3

tmux new-window -t fuzz-cmd:4 -n 'fuzz-cmd-sniff'
fuzz_tmux sniff fuzz-cmd:4

tmux new-window -t fuzz-cmd:5 -n 'fuzz-cmd-sting'
fuzz_tmux sting fuzz-cmd:5

tmux new-window -t fuzz-cmd:6 -n 'fuzz-cmd-tbit'
fuzz_tmux tbit fuzz-cmd:6

tmux new-window -t fuzz-cmd:7 -n 'fuzz-cmd-trace'
fuzz_tmux trace fuzz-cmd:7

tmux new-window -t fuzz-cmd:8 -n 'fuzz-cmd-udpprobe'
fuzz_tmux udpprobe fuzz-cmd:8
