#!/bin/sh

set -e

FUZZDIR=${1?}

mkdir -p ${FUZZDIR}

if [ -r "/proc/sys/kernel/core_pattern" ] ; then
    line=$(head -n 1 /proc/sys/kernel/core_pattern)
    if [ "$line" != "core" ] ; then
	echo "unexpected core pattern $line"
	exit 1
    fi
fi

prepare()
{
    ARG_TYPE=$1
    mkdir -p ${FUZZDIR}/${ARG_TYPE}/input

    if [ "$ARG_TYPE" = "warts2json" ] ; then
	./unit_warts dump ${FUZZDIR}/${ARG_TYPE}/input
    else
	./unit_${ARG_TYPE} dump ${FUZZDIR}/${ARG_TYPE}/input
    fi

    afl-cmin -i ${FUZZDIR}/${ARG_TYPE}/input -o ${FUZZDIR}/${ARG_TYPE}/testcases -- ./fuzz_${ARG_TYPE} @@
}

fuzz_tmux()
{
    ARG_TYPE=$1
    ARG_WINDOW=$2

    tmux send-keys -t ${ARG_WINDOW} "AFL_TMPDIR=${FUZZDIR}/${ARG_TYPE} AFL_SKIP_CPUFREQ=1 AFL_NO_AFFINITY=1 afl-fuzz -i ${FUZZDIR}/${ARG_TYPE}/testcases -o ${FUZZDIR}/${ARG_TYPE}/findings -- ./fuzz_${ARG_TYPE} @@" C-m
}

prepare cmd_dealias
prepare cmd_host
prepare cmd_http
prepare cmd_ping
prepare cmd_sniff
prepare cmd_sting
prepare cmd_tbit
prepare cmd_trace
prepare cmd_tracelb
prepare cmd_udpprobe
prepare dl_parse_arp
prepare dl_parse_ip
prepare host_rr_list
prepare warts
prepare warts2json

WIN=0
tmux new-session -d -s fuzz-scamper
tmux rename-window -t fuzz-scamper:${WIN} 'fuzz-cmd-dealias'
fuzz_tmux cmd_dealias fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-host'
fuzz_tmux cmd_host fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-http'
fuzz_tmux cmd_http fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-ping'
fuzz_tmux cmd_ping fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-sniff'
fuzz_tmux cmd_sniff fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-sting'
fuzz_tmux cmd_sting fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-tbit'
fuzz_tmux cmd_tbit fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-trace'
fuzz_tmux cmd_trace fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-tracelb'
fuzz_tmux cmd_tracelb fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-cmd-udpprobe'
fuzz_tmux cmd_udpprobe fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-dl-parse-arp'
fuzz_tmux dl_parse_arp fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-dl-parse-ip'
fuzz_tmux dl_parse_ip fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-host-rr-list'
fuzz_tmux host_rr_list fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-warts'
fuzz_tmux warts fuzz-scamper:${WIN}

WIN=`expr ${WIN} + 1`
tmux new-window -t fuzz-scamper:${WIN} -n 'fuzz-warts2json'
fuzz_tmux warts2json fuzz-scamper:${WIN}
