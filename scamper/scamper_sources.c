/*
 * scamper_source
 *
 * $Id: scamper_sources.c,v 1.91 2025/05/28 07:10:37 mjl Exp $
 *
 * Copyright (C) 2004-2006 Matthew Luckie
 * Copyright (C) 2006-2011 The University of Waikato
 * Copyright (C) 2012      Matthew Luckie
 * Copyright (C) 2012      The Regents of the University of California
 * Copyright (C) 2018-2024 Matthew Luckie
 * Copyright (C) 2023      The Regents of the University of California
 * Author: Matthew Luckie
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "internal.h"

#include "scamper.h"
#include "scamper_addr.h"
#include "scamper_list.h"
#include "scamper_list_int.h"
#include "scamper_task.h"
#include "scamper_file.h"
#include "scamper_outfiles.h"
#include "scamper_sources.h"
#include "scamper_cyclemon.h"

#ifndef DISABLE_SCAMPER_TRACE
#include "trace/scamper_trace_cmd.h"
#include "trace/scamper_trace_do.h"
#endif
#ifndef DISABLE_SCAMPER_PING
#include "ping/scamper_ping_cmd.h"
#include "ping/scamper_ping_do.h"
#endif
#ifndef DISABLE_SCAMPER_TRACELB
#include "tracelb/scamper_tracelb_cmd.h"
#include "tracelb/scamper_tracelb_do.h"
#endif
#ifndef DISABLE_SCAMPER_DEALIAS
#include "dealias/scamper_dealias_cmd.h"
#include "dealias/scamper_dealias_do.h"
#endif
#include "neighbourdisc/scamper_neighbourdisc_cmd.h"
#include "neighbourdisc/scamper_neighbourdisc_do.h"
#ifndef DISABLE_SCAMPER_TBIT
#include "tbit/scamper_tbit_cmd.h"
#include "tbit/scamper_tbit_do.h"
#endif
#ifndef DISABLE_SCAMPER_STING
#include "sting/scamper_sting_cmd.h"
#include "sting/scamper_sting_do.h"
#endif
#ifndef DISABLE_SCAMPER_SNIFF
#include "sniff/scamper_sniff_cmd.h"
#include "sniff/scamper_sniff_do.h"
#endif
#ifndef DISABLE_SCAMPER_HOST
#include "host/scamper_host_cmd.h"
#include "host/scamper_host_do.h"
#endif
#ifndef DISABLE_SCAMPER_HTTP
#include "http/scamper_http_cmd.h"
#include "http/scamper_http_do.h"
#endif
#ifndef DISABLE_SCAMPER_UDPPROBE
#include "udpprobe/scamper_udpprobe_cmd.h"
#include "udpprobe/scamper_udpprobe_do.h"
#endif

#include "scamper_debug.h"

#include "utils.h"
#include "mjl_list.h"
#include "mjl_splaytree.h"

/*
 * scamper_source
 *
 * this structure maintains state regarding tasks that come from a particular
 * source.  some of the state is stored in scamper_list_t and scamper_cycle_t
 * structures with the resulting data object.
 *
 */
struct scamper_source
{
  /* basic data collection properties to store with the source */
  scamper_list_t               *list;
  scamper_cycle_t              *cycle;

  /* properties of the source */
  uint32_t                      priority;
  int                           type;
  int                           refcnt;
  scamper_outfile_t            *sof;
  scamper_cyclemon_t           *cyclemon;

  /*
   * commands:     a list of commands for the source that are queued, ready to
   *               be passed out as tasks
   * cycle_points: the number of cycle points in the commands list
   * tasks:        a list of tasks currently active from the source.
   * id:           the next id number to assign
   * idtree:       a tree of id numbers currently in use
   */
  dlist_t                      *commands;
  int                           cycle_points;
  dlist_t                      *tasks;
  uint32_t                      id;
  splaytree_t                  *idtree;

  /*
   * nodes to keep track of whether the source is in the active or blocked
   * lists, and a node to keep track of the source in a splaytree
   */
  void                         *list_;
  void                         *list_node;
  splaytree_node_t             *tree_node;

  /* data and callback functions specific to the type of source this is */
  void                         *data;
  int                         (*take)(void *data);
  void                        (*freedata)(void *data);
  int                         (*isfinished)(void *data);
  char *                      (*tostr)(void *data, char *str, size_t len);
};

struct scamper_sourcetask
{
  scamper_source_t *source;
  scamper_task_t   *task;
  dlist_node_t     *node;
  uint32_t          id;
  splaytree_node_t *idnode;
};

/*
 * command_funcs
 *
 * a utility struct to save passing loads of functions around individually
 * that are necessary to start a probe command.
 */
typedef struct command_func
{
  char             *command;
  size_t            len;
  void           *(*allocdata)(char *cmd, char *errbuf, size_t errlen);
  scamper_task_t *(*alloctask)(void *data,
			       scamper_list_t *list, scamper_cycle_t *cycle,
			       char *errbuf, size_t errlen);
  void            (*freedata)(void *data);
  uint32_t        (*userid)(void *data);
  int             (*enabled)(void);
} command_func_t;

static const command_func_t command_funcs[] = {
#ifndef DISABLE_SCAMPER_TRACE
  {
    "trace", 5,
    scamper_do_trace_alloc,
    scamper_do_trace_alloctask,
    scamper_do_trace_free,
    scamper_do_trace_userid,
    scamper_do_trace_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_PING
  {
    "ping", 4,
    scamper_do_ping_alloc,
    scamper_do_ping_alloctask,
    scamper_do_ping_free,
    scamper_do_ping_userid,
    scamper_do_ping_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_TRACELB
  {
    "tracelb", 7,
    scamper_do_tracelb_alloc,
    scamper_do_tracelb_alloctask,
    scamper_do_tracelb_free,
    scamper_do_tracelb_userid,
    scamper_do_tracelb_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_DEALIAS
  {
    "dealias", 7,
    scamper_do_dealias_alloc,
    scamper_do_dealias_alloctask,
    scamper_do_dealias_free,
    scamper_do_dealias_userid,
    scamper_do_dealias_enabled,
  },
#endif
  {
    "neighbourdisc", 13,
    scamper_do_neighbourdisc_alloc,
    scamper_do_neighbourdisc_alloctask,
    scamper_do_neighbourdisc_free,
    scamper_do_neighbourdisc_userid,
    scamper_do_neighbourdisc_enabled,
  },
#ifndef DISABLE_SCAMPER_TBIT
  {
    "tbit", 4,
    scamper_do_tbit_alloc,
    scamper_do_tbit_alloctask,
    scamper_do_tbit_free,
    scamper_do_tbit_userid,
    scamper_do_tbit_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_STING
  {
    "sting", 5,
    scamper_do_sting_alloc,
    scamper_do_sting_alloctask,
    scamper_do_sting_free,
    scamper_do_sting_userid,
    scamper_do_sting_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_SNIFF
  {
    "sniff", 5,
    scamper_do_sniff_alloc,
    scamper_do_sniff_alloctask,
    scamper_do_sniff_free,
    scamper_do_sniff_userid,
    scamper_do_sniff_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_HOST
  {
    "host", 4,
    scamper_do_host_alloc,
    scamper_do_host_alloctask,
    scamper_do_host_free,
    scamper_do_host_userid,
    scamper_do_host_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_HTTP
  {
    "http", 4,
    scamper_do_http_alloc,
    scamper_do_http_alloctask,
    scamper_do_http_free,
    scamper_do_http_userid,
    scamper_do_http_enabled,
  },
#endif
#ifndef DISABLE_SCAMPER_UDPPROBE
  {
    "udpprobe", 8,
    scamper_do_udpprobe_alloc,
    scamper_do_udpprobe_alloctask,
    scamper_do_udpprobe_free,
    scamper_do_udpprobe_userid,
    scamper_do_udpprobe_enabled,
  },
#endif
};

static size_t command_funcc = sizeof(command_funcs) / sizeof(command_func_t);

/*
 * command
 *
 *  type:  COMMAND_PROBE or COMMAND_CYCLE or COMMAND_TASK
 *  funcs: pointer to appropriate command_func_t
 *  data:  pointer to data allocated for task
 *  param: additional parameters specific to the command's type.
 */
typedef struct command
{
  uint8_t                   type;

  union
  {
    struct command_probe
    {
      const command_func_t *funcs;
      void                 *data;
      scamper_cyclemon_t   *cyclemon;
    } pr;
    scamper_cycle_t        *cycle;
    scamper_sourcetask_t   *sourcetask;
  } un;
} command_t;

#define COMMAND_PROBE      0x00
#define COMMAND_CYCLE      0x01
#define COMMAND_TASK       0x02

#define COMMAND_TYPE_MIN   0x00
#define COMMAND_TYPE_MAX   0x02

/*
 * global variables for managing sources:
 *
 * a source is stored in one of two lists depending on its state.  it is
 * either stored in the active list, a round-robin circular list, or in
 * the blocked list.
 *
 * the source, if any, currently being used (that is, has not used up its
 * priority quantum) is pointed to by source_cur.  the number of tasks that
 * have been read from the current source in this rotation is held in
 * source_cnt.
 *
 * the sources are stored in a tree that is searchable by name.
 */
static clist_t          *active      = NULL;
static dlist_t          *blocked     = NULL;
static dlist_t          *finished    = NULL;
static scamper_source_t *source_cur  = NULL;
static uint32_t          source_cnt  = 0;
static splaytree_t      *source_tree = NULL;

/* forward declare */
static void source_free(scamper_source_t *source);

#if !defined(NDEBUG) && defined(SOURCES_DEBUG)
static int command_assert(void *item, void *param)
{
  command_t *c = item;
  int *cycles = param;

  assert(c->type <= COMMAND_TYPE_MAX);

  switch(c->type)
    {
    case COMMAND_PROBE:
      assert(c->un.pr.data != NULL);
      assert(c->un.pr.cyclemon != NULL);
      break;

    case COMMAND_TASK:
      assert(c->un.sourcetask != NULL);
      break;

    case COMMAND_CYCLE:
      *cycles = *cycles + 1;
      break;
    }

  return 0;
}

static int source_assert(void *item, void *param)
{
  scamper_source_t *s = item;
  dlist_node_t *dn;
  int cycles;

  /* check the source for valid refcnts */
  assert(s->refcnt > 0);
  if(s->list != NULL)
    assert(s->list->refcnt > 0);
  if(s->cycle != NULL)
    assert(s->cycle->refcnt > 0);
  if(s->sof != NULL)
    assert(scamper_outfile_getrefcnt(s->sof) > 0);

  /* simple checks on parameters in the source struct */
  assert(s->type >= SCAMPER_SOURCE_TYPE_MIN);
  assert(s->type <= SCAMPER_SOURCE_TYPE_MAX);
  assert(s->tasks != NULL);

  /* make sure the list pointer makes sense */
  assert(s->list_ != NULL);
  assert(s->list_ == active || s->list_ == blocked || s->list_ == finished);
  assert(s->list_ == param);

  /* sanity check queued commands */
  assert(s->commands != NULL);
  cycles = 0;
  dlist_foreach(s->commands, command_assert, &cycles);
  /* XXX: should cycles == s->cycle_points? */

  return 0;
}

static void sources_assert(void)
{
  assert(active != NULL);
  clist_foreach(active, source_assert, active);
  assert(blocked != NULL);
  dlist_foreach(blocked, source_assert, blocked);
  assert(finished != NULL);
  dlist_foreach(finished, source_assert, finished);
  return;
}
#else
#define sources_assert()((void)0)
#endif

static int source_refcnt_dec(scamper_source_t *source)
{
  assert(source->refcnt > 0);
  source->refcnt--;
  return source->refcnt;
}

static scamper_sourcetask_t *sourcetask_alloc(scamper_source_t *source,
					      scamper_task_t *task)
{
  scamper_sourcetask_t *st = NULL;
  if((st = malloc_zero(sizeof(scamper_sourcetask_t))) == NULL)
    goto err;
  if((st->node = dlist_tail_push(source->tasks, st)) == NULL)
    goto err;
  st->source = scamper_source_use(source);
  st->task = task;
  return st;

 err:
  if(st != NULL) free(st);
  return NULL;
}

static int idtree_cmp(const scamper_sourcetask_t *a,
		      const scamper_sourcetask_t *b)
{
  if(a->id < b->id) return -1;
  if(a->id > b->id) return  1;
  return 0;
}

static command_t *command_alloc(int type)
{
  command_t *cmd;
  if((cmd = malloc_zero(sizeof(command_t))) == NULL)
    {
      printerror(__func__, "could not malloc command");
      return NULL;
    }
  cmd->type = type;
  return cmd;
}

static void command_free(command_t *command)
{
  if(command->type == COMMAND_PROBE)
    {
      if(command->un.pr.funcs->freedata != NULL && command->un.pr.data != NULL)
	command->un.pr.funcs->freedata(command->un.pr.data);
      if(command->un.pr.cyclemon != NULL)
	scamper_cyclemon_unuse(command->un.pr.cyclemon);
    }

  free(command);
  return;
}

/*
 * command_cycle
 *
 * given the commands list, append a cycle command to it.
 */
static int command_cycle(scamper_source_t *source, scamper_cycle_t *cycle)
{
  command_t *command = NULL;

  if((command = command_alloc(COMMAND_CYCLE)) == NULL)
    goto err;
  command->un.cycle = cycle;
  if(dlist_tail_push(source->commands, command) == NULL)
    goto err;
  source->cycle_points++;

  return 0;

 err:
  if(command != NULL) command_free(command);
  return -1;
}

/*
 * source_next
 *
 * advance to the next source to read addresses from, and reset the
 * current count of how many addresses have been returned off the list
 * for this source-cycle
 */
static scamper_source_t *source_next(void)
{
  void *node;

  if((node = clist_node_next(source_cur->list_node)) != source_cur->list_node)
    source_cur = clist_node_item(node);

  source_cnt = 0;

  return source_cur;
}

/*
 * source_active_detach
 *
 * detach the source out of the active list.  move to the next source
 * if it is the current source that is being read from.
 */
static void source_active_detach(scamper_source_t *source)
{
  void *node;

  assert(source->list_ == active);

  source_cur = NULL;
  source_cnt = 0;

  if(source->list_node != NULL)
    {
      if((node = clist_node_next(source->list_node)) != source->list_node)
	source_cur = clist_node_item(node);

      clist_node_pop(active, source->list_node);
    }

  source->list_     = NULL;
  source->list_node = NULL;

  return;
}

/*
 * source_blocked_detach
 *
 * detach the source out of the blocked list.
 */
static void source_blocked_detach(scamper_source_t *source)
{
  assert(source->list_ == blocked);

  dlist_node_pop(blocked, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_finished_detach
 *
 * detach the source out of the finished list.
 */
static void source_finished_detach(scamper_source_t *source)
{
  assert(source->list_ == finished);

  dlist_node_pop(finished, source->list_node);
  source->list_     = NULL;
  source->list_node = NULL;
  return;
}

/*
 * source_active_attach
 *
 * some condition has changed, which may mean the source can go back onto
 * the active list for use by the probing process.
 *
 * a caller MUST NOT assume that the source will necessarily end up on the
 * active list after calling this function.  for example, source_active_attach
 * may be called when new tasks are added to the command list.  however, the
 * source may have a zero priority, which means probing this source is
 * currently paused.
 */
static int source_active_attach(scamper_source_t *source)
{
  if(source->list_ == active)
    return 0;

  if(source->list_ == finished)
    return -1;

  if(source->list_ == blocked)
    {
      /* if the source has a zero priority, it must remain blocked */
      if(source->priority == 0)
	return 0;
      source_blocked_detach(source);
    }

  if((source->list_node = clist_tail_push(active, source)) == NULL)
    return -1;
  source->list_ = active;

  if(source_cur == NULL)
    {
      source_cur = source;
      source_cnt = 0;
    }

  return 0;
}

/*
 * source_blocked_attach
 *
 * put the specified source onto the blocked list.
 */
static int source_blocked_attach(scamper_source_t *source)
{
  if(source->list_ == blocked)
    return 0;

  if(source->list_ == finished)
    return -1;

  if(source->list_node != NULL)
    source_active_detach(source);

  if((source->list_node = dlist_tail_push(blocked, source)) == NULL)
    return -1;
  source->list_ = blocked;

  return 0;
}

/*
 * source_finished_attach
 *
 * put the specified source onto the finished list.
 */
static int source_finished_attach(scamper_source_t *source)
{
  if(source->list_ == finished)
    return 0;

  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);

  if((source->list_node = dlist_tail_push(finished, source)) == NULL)
    return -1;

  source->list_ = finished;
  return 0;
}

/*
 * source_command_unhold
 *
 * the task this command was blocked on has now completed.
 * put the command at the front of the source's list of things to do.
 */
void scamper_source_task_unhold(scamper_task_t *task)
{
  scamper_sourcetask_t *st = NULL;
  scamper_source_t *source = NULL;
  command_t *cmd = NULL;

  if((st = scamper_task_getsourcetask(task)) == NULL ||
     (source = st->source) == NULL)
    return;

  if((cmd = command_alloc(COMMAND_TASK)) == NULL)
    goto err;
  cmd->un.sourcetask = st;
  if(dlist_head_push(source->commands, cmd) == NULL)
    goto err;
  source_active_attach(source);
  return;

 err:
  if(cmd != NULL) free(cmd);
  return;
}

/*
 * source_task_install
 *
 * code to install a task if possible and put it onhold if not.
 *
 */
static int source_task_install(scamper_source_t *source,
			       scamper_sourcetask_t *st, scamper_task_t **out)
{
  scamper_task_t *task = st->task;
  scamper_task_t *blocker;

  scamper_task_sig_prepare(task);

  /* nothing blocking the task from running (blocker == NULL); install it */
  if((blocker = scamper_task_sig_block(task)) == NULL)
    {
      if(scamper_task_sig_install(task) != 0)
	return -1;
      *out = task;
    }
  else
    {
      /*
       * something is blocking the command from running.  the blocking
       * task is in the blocker variable.
       */
      if(scamper_task_onhold(blocker, task) != 0)
	return -1;
      *out = NULL;
    }

  return 0;
}

static int command_task_handle(scamper_source_t *source, command_t *command,
			       scamper_task_t **task_out)
{
  scamper_sourcetask_t *st = command->un.sourcetask;
  command_free(command);
  return source_task_install(source, st, task_out);
}

static int command_probe_handle(scamper_source_t *source, command_t *command,
				scamper_task_t **task_out)
{
  const command_func_t *funcs = command->un.pr.funcs;
  scamper_sourcetask_t *st = NULL;
  scamper_cycle_t *cycle;
  scamper_task_t *task = NULL;
  char errbuf[256];

  sources_assert();

  /* get a pointer to the cycle for *this* task */
  cycle = scamper_cyclemon_cycle(command->un.pr.cyclemon);

  /* allocate the task structure to keep everything together */
  if((task = funcs->alloctask(command->un.pr.data, source->list, cycle,
			      errbuf, sizeof(errbuf))) == NULL)
    {
      if(errbuf[0] != '\0')
	printerror_msg(__func__, "%s", errbuf);
      else
	printerror_msg(__func__, "alloctask failed");
      goto err;
    }
  scamper_task_setcyclemon(task, command->un.pr.cyclemon);
  command->un.pr.data = NULL;
  command_free(command);
  command = NULL;

  /*
   * keep a record in the source that this task is now active
   * pass the cyclemon structure to the task
   */
  if((st = sourcetask_alloc(source, task)) == NULL)
    goto err;
  task = NULL;
  scamper_task_setsourcetask(st->task, st);

  if(source_task_install(source, st, task_out) != 0)
    goto err;

  sources_assert();
  return 0;

 err:
  if(st != NULL) scamper_sourcetask_free(st);
  if(task != NULL) scamper_task_free(task);
  if(command != NULL) command_free(command);
  sources_assert();
  return -1;
}

/*
 * command_cycle_handle
 *
 *
 */
static int command_cycle_handle(scamper_source_t *source, command_t *command)
{
  scamper_cycle_t *cycle = command->un.cycle;
  scamper_file_t *file;
  struct timeval tv;
  char hostname[MAXHOSTNAMELEN];

  sources_assert();

  /* get the hostname of the system for the cycle point */
  if(gethostname(hostname, sizeof(hostname)) == 0)
    cycle->hostname = strdup(hostname);

  /* get a timestamp for the cycle start point */
  gettimeofday_wrap(&tv);
  cycle->start_time = (uint32_t)tv.tv_sec;

  /* write a cycle start point to disk if there is a file to do so */
  if(source->sof != NULL &&
     (file = scamper_outfile_getfile(source->sof)) != NULL)
    {
      scamper_file_write_cycle_start(file, cycle);
    }

  command_free(command);
  sources_assert();
  return 0;
}

/*
 * source_cycle_finish
 *
 * when the last cycle is written to disk, we can start on the next cycle.
 */
static void source_cycle_finish(scamper_cycle_t *cycle,
				scamper_source_t *source,
				scamper_outfile_t *outfile)
{
  scamper_file_t *sf;
  struct timeval tv;

  sources_assert();

  /* timestamp when the cycle ends */
  gettimeofday_wrap(&tv);
  cycle->stop_time = (uint32_t)tv.tv_sec;

  /* write the cycle stop record out */
  if(outfile != NULL)
    {
      sf = scamper_outfile_getfile(outfile);
      scamper_file_write_cycle_stop(sf, cycle);
    }

  if(source != NULL)
    source->cycle_points--;

  sources_assert();
  return;
}

/*
 * source_cycle
 *
 * allocate and initialise a cycle start object for the source.
 * write the cycle start to disk.
 */
static int source_cycle(scamper_source_t *source, uint32_t cycle_id)
{
  scamper_cyclemon_t *cyclemon = NULL;
  scamper_cycle_t *cycle = NULL;

  sources_assert();

  /* allocate the new cycle object */
  if((cycle = scamper_cycle_alloc(source->list)) == NULL)
    {
      printerror(__func__, "could not alloc new cycle");
      goto err;
    }

  /* assign the cycle id */
  cycle->id = cycle_id;

  /* allocate structure to monitor references to the new cycle */
  if((cyclemon = scamper_cyclemon_alloc(cycle, source_cycle_finish, source,
					source->sof)) == NULL)
    {
      printerror(__func__, "could not alloc new cyclemon");
      goto err;
    }

  /* append the cycle record to the source's commands list */
  if(command_cycle(source, cycle) != 0)
    {
      printerror(__func__, "could not insert cycle marker");
      goto err;
    }

  /*
   * if there is a previous cycle object associated with the source, then
   * free that.  also free the cyclemon.
   */
  if(source->cycle != NULL)
    scamper_cycle_free(source->cycle);
  if(source->cyclemon != NULL)
    scamper_cyclemon_unuse(source->cyclemon);

  /* store the cycle and we're done */
  source->cycle = cycle;
  source->cyclemon = cyclemon;

  sources_assert();
  return 0;

 err:
  if(cyclemon != NULL) scamper_cyclemon_free(cyclemon);
  if(cycle != NULL) scamper_cycle_free(cycle);
  sources_assert();
  return -1;
}

static int source_cmp(const scamper_source_t *a, const scamper_source_t *b)
{
  return strcasecmp(b->list->name, a->list->name);
}

/*
 * source_flush_commands
 *
 * remove the ability for the source to supply any more commands, and remove
 * any commands it currently has queued.
 */
static void source_flush_commands(scamper_source_t *source)
{
  command_t *command;

  sources_assert();

  if(source->data != NULL)
    source->freedata(source->data);

  source->data        = NULL;
  source->take        = NULL;
  source->freedata    = NULL;
  source->isfinished  = NULL;
  source->tostr       = NULL;

  if(source->commands != NULL)
    {
      while((command = dlist_head_pop(source->commands)) != NULL)
	command_free(command);
      dlist_free(source->commands);
      source->commands = NULL;
    }

  sources_assert();
  return;
}

/*
 * source_flush_tasks
 *
 * stop all active tasks that originated from the specified source.
 */
static void source_flush_tasks(scamper_source_t *source)
{
  scamper_sourcetask_t *st;

  sources_assert();

  /* flush all active tasks. XXX: what about completed tasks? */
  if(source->tasks != NULL)
    {
      /* scamper_task_free will free scamper_sourcetask_t */
      while((st = dlist_head_pop(source->tasks)) != NULL)
	{
	  st->node = NULL;
	  scamper_task_free(st->task);
	}
      dlist_free(source->tasks);
      source->tasks = NULL;
    }

  sources_assert();
  return;
}

/*
 * source_detach
 *
 * remove the source from sources management.
 */
static void source_detach(scamper_source_t *source)
{
  /* detach the source from whatever list it is in */
  if(source->list_ == active)
    source_active_detach(source);
  else if(source->list_ == blocked)
    source_blocked_detach(source);
  else if(source->list_ == finished)
    source_finished_detach(source);

  assert(source->list_ == NULL);
  assert(source->list_node == NULL);

  /* remove the source from the tree */
  if(source->tree_node != NULL)
    {
      splaytree_remove_node(source_tree, source->tree_node);
      source->tree_node = NULL;

      /* decrement the reference count held for the source */
      if(source_refcnt_dec(source) == 0)
	source_free(source);
    }

  return;
}

/*
 * scamper_source_isfinished
 *
 * determine if the source has queued all it has to do.
 * note that the tasks list may still have active items currently processing.
 */
int scamper_source_isfinished(scamper_source_t *source)
{
  sources_assert();

  /* if there are commands queued, then the source cannot be finished */
  if(source->commands != NULL && dlist_count(source->commands) > 0)
    return 0;

  /* if there are still tasks underway, the source is not finished */
  if(source->tasks != NULL && dlist_count(source->tasks) > 0)
    return 0;

  /*
   * if the source still has commands to come, then it is not finished.
   * the callback checks with the source-type specific code to see if there
   * are commands to come.
   */
  if(source->isfinished != NULL && source->isfinished(source->data) == 0)
    return 0;

  return 1;
}

/*
 * scamper_source_finished
 *
 * when a source is known to be finished (say a control socket that will no
 * longer be supplying tasks)
 */
void scamper_source_finished(scamper_source_t *source)
{
  sources_assert();
  assert(scamper_source_isfinished(source) != 0);
  if(source->cyclemon != NULL)
    {
      assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }
  source_finished_attach(source);
  sources_assert();
  return;
}

/*
 * source_free
 *
 * clean up the source
 */
static void source_free(scamper_source_t *source)
{
  char buf[512];

  assert(source != NULL);
  assert(source->refcnt == 0);

  if(scamper_source_tostr(source, buf, sizeof(buf)) != NULL)
    scamper_debug(__func__, "%s", buf);

  if(source->cyclemon != NULL)
    {
      scamper_cyclemon_source_detach(source->cyclemon);
      scamper_cyclemon_unuse(source->cyclemon);
      source->cyclemon = NULL;
    }

  /* pull the source out of sources management */
  source_detach(source);

  /* empty the source of commands */
  if(source->commands != NULL)
    source_flush_commands(source);

  /* empty the source of tasks */
  if(source->tasks != NULL)
    source_flush_tasks(source);

  /* don't need the idtree any more */
  if(source->idtree != NULL)
    {
      assert(splaytree_count(source->idtree) == 0);
      splaytree_free(source->idtree, NULL);
    }

  /* release this structure's hold on the scamper_outfile */
  if(source->sof != NULL) scamper_outfile_free(source->sof);

  if(source->list != NULL) scamper_list_free(source->list);
  if(source->cycle != NULL) scamper_cycle_free(source->cycle);

  free(source);
  sources_assert();
  return;
}

/*
 * scamper_source_getname
 *
 * return the name of the source
 */
const char *scamper_source_getname(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->name;
}

/*
 * scamper_source_getdescr
 *
 * return the description for the source
 */
const char *scamper_source_getdescr(const scamper_source_t *source)
{
  if(source->list == NULL) return NULL;
  return source->list->descr;
}

/*
 * scamper_source_getoutfile
 *
 * return the name of the outfile associated with the source
 */
const char *scamper_source_getoutfile(const scamper_source_t *source)
{
  return scamper_outfile_getname(source->sof);
}

/*
 * scamper_source_getlistid
 *
 * return the list id for the source
 */
uint32_t scamper_source_getlistid(const scamper_source_t *source)
{
  return source->list->id;
}

/*
 * scamper_source_getcycleid
 *
 * return the cycle id for the source
 */
uint32_t scamper_source_getcycleid(const scamper_source_t *source)
{
  return source->cycle->id;
}

/*
 * scamper_source_getpriority
 *
 * return the priority value for the source
 */
uint32_t scamper_source_getpriority(const scamper_source_t *source)
{
  return source->priority;
}

const char *scamper_source_type_tostr(const scamper_source_t *source)
{
  switch(source->type)
    {
    case SCAMPER_SOURCE_TYPE_FILE:    return "file";
    case SCAMPER_SOURCE_TYPE_CMDLINE: return "cmdline";
    case SCAMPER_SOURCE_TYPE_CONTROL: return "control";
    }

  return NULL;
}

char *scamper_source_tostr(const scamper_source_t *src, char *buf, size_t len)
{
  char tmp[512];
  size_t off = 0;

  if(src->list == NULL || src->list->name == NULL)
    return NULL;

  string_concat2(buf, len, &off, "name ", src->list->name);
  if(src->tostr != NULL && src->tostr(src->data, tmp, sizeof(tmp)) != NULL)
    {
      string_concatc(buf, len, &off, ' ');
      string_concat(buf, len, &off, tmp);
    }

  return buf;
}

/*
 * scamper_source_getcommandcount
 *
 * return the number of commands queued for the source
 */
int scamper_source_getcommandcount(const scamper_source_t *source)
{
  if(source->commands != NULL)
    return dlist_count(source->commands);
  return -1;
}

int scamper_source_getcyclecount(const scamper_source_t *source)
{
  return source->cycle_points;
}

int scamper_source_gettaskcount(const scamper_source_t *source)
{
  if(source->tasks != NULL)
    return dlist_count(source->tasks);
  return -1;
}

int scamper_source_gettype(const scamper_source_t *source)
{
  return source->type;
}

void *scamper_source_getdata(const scamper_source_t *source)
{
  return source->data;
}

static const command_func_t *command_func_get(const char *command)
{
  const command_func_t *func = NULL;
  size_t i;

  for(i=0; i<command_funcc; i++)
    {
      func = &command_funcs[i];
      if(strncasecmp(command, func->command, func->len) == 0 &&
	 isspace((unsigned char)command[func->len]) &&
	 command[func->len] != '\0')
	{
	  return func;
	}
    }

  return NULL;
}

/*
 * command_func_allocdata:
 *
 * make a copy of the options, since the next function may modify the
 * contents of it
 */
static void *command_func_allocdata(const command_func_t *f, const char *cmd,
				    char *errbuf, size_t errlen)
{
  char *opts = NULL;
  void *data;
  if((opts = strdup(cmd + f->len)) == NULL)
    {
      printerror(__func__, "could not strdup cmd opts");
      return NULL;
    }
  data = f->allocdata(opts, errbuf, errlen);
  free(opts);
  return data;
}

int scamper_source_halttask(scamper_source_t *source, uint32_t id)
{
  scamper_sourcetask_t *st, fm;
  command_t *cmd;
  dlist_node_t *no;

  sources_assert();

  fm.id = id;
  if(source->idtree == NULL)
    return -1;
  if((st = splaytree_find(source->idtree, &fm)) == NULL)
    return -1;

  scamper_task_halt(st->task);

  for(no=dlist_head_node(source->commands); no != NULL; no=dlist_node_next(no))
    {
      cmd = dlist_node_item(no);
      if(cmd->type == COMMAND_TASK && cmd->un.sourcetask == st)
	{
	  cmd = dlist_node_pop(source->commands, no);
	  command_free(cmd);
	  break;
	}
    }

  sources_assert();
  return 0;
}

/*
 * scamper_source_command2
 *
 * the given command is created as a task immediately and assigned an id
 * which allows the command to be halted.  used by the control socket code.
 */
int scamper_source_command2(scamper_source_t *s, const char *command,
			    uint32_t *id, char *errbuf, size_t errlen)
{
  const command_func_t *f = NULL;
  scamper_sourcetask_t *st = NULL;
  scamper_task_t *task = NULL;
  command_t *cmd = NULL;
  void *data = NULL;

  errbuf[0] = '\0';

  sources_assert();

  if(s->idtree == NULL &&
     (s->idtree = splaytree_alloc((splaytree_cmp_t)idtree_cmp)) == NULL)
    {
      snprintf(errbuf, errlen, "could not alloc idtree");
      goto err;
    }

  if((f = command_func_get(command)) == NULL)
    {
      snprintf(errbuf, errlen, "could not determine command type");
      goto err;
    }
  if(f->enabled() == 0)
    {
      snprintf(errbuf, errlen, "%s disabled", f->command);
      goto err;
    }
  if((data = command_func_allocdata(f, command, errbuf, errlen)) == NULL)
    goto err;
  if((task = f->alloctask(data, s->list, s->cycle, errbuf, errlen)) == NULL)
    goto err;
  data = NULL;

  /*
   * keep a record in the source that this task is now active
   * pass the cyclemon structure to the task
   */
  if((st = sourcetask_alloc(s, task)) == NULL)
    {
      snprintf(errbuf, errlen, "could not sourcetask_alloc");
      goto err;
    }
  scamper_task_setsourcetask(task, st);
  scamper_task_setcyclemon(task, s->cyclemon);
  task = NULL;

  /* assign an id.  assume for now this will be enough to ensure uniqueness */
  st->id = *id = s->id;
  if(++s->id == 0) s->id = 1;
  if((st->idnode = splaytree_insert(s->idtree, st)) == NULL)
    {
      snprintf(errbuf, errlen, "could not add to idtree");
      goto err;
    }

  if((cmd = command_alloc(COMMAND_TASK)) == NULL)
    {
      snprintf(errbuf, errlen, "could not command_alloc");
      goto err;
    }
  cmd->un.sourcetask = st;

  if(dlist_tail_push(s->commands, cmd) == NULL)
    {
      snprintf(errbuf, errlen, "could not add to commands list");
      goto err;
    }

  source_active_attach(s);
  sources_assert();
  return 0;

 err:
  /* XXX free scamper_sourcetask_t ?? */
  if(data != NULL) f->freedata(data);
  if(cmd != NULL) command_free(cmd);
  sources_assert();
  return -1;
}

/*
 * scamper_source_command
 *
 */
int scamper_source_command(scamper_source_t *source, const char *command)
{
  const command_func_t *func = NULL;
  command_t *cmd = NULL;
  char *opts = NULL;
  void *data = NULL;
  char errbuf[256];

  sources_assert();

  if((func = command_func_get(command)) == NULL)
    goto err;
  if(func->enabled() == 0)
    {
      printerror_msg(__func__, "%s disabled", func->command);
      goto err;
    }

  errbuf[0] = '\0';
  if((data = command_func_allocdata(func, command,
				    errbuf, sizeof(errbuf))) == NULL)
    {
      if(errbuf[0] != '\0')
	printerror_msg(__func__, "%s", errbuf);
      else
	printerror_msg(__func__, "could not parse command");
      goto err;
    }

  if((cmd = command_alloc(COMMAND_PROBE)) == NULL)
    goto err;
  cmd->un.pr.funcs    = func;
  cmd->un.pr.data     = data;
  cmd->un.pr.cyclemon = scamper_cyclemon_use(source->cyclemon);

  if(dlist_tail_push(source->commands, cmd) == NULL)
    goto err;

  source_active_attach(source);
  sources_assert();
  return 0;

 err:
  if(opts != NULL) free(opts);
  if(data != NULL) func->freedata(data);
  if(cmd != NULL) free(cmd);
  sources_assert();
  return -1;
}

scamper_source_t *scamper_sourcetask_getsource(scamper_sourcetask_t *st)
{
  return st->source;
}

uint32_t scamper_sourcetask_getid(const scamper_sourcetask_t *st)
{
  return st->id;
}

/*
 * scamper_sourcetask_free
 *
 * when a task completes, this function is called.  it allows the source
 * to keep track of which tasks came from it.
 */
void scamper_sourcetask_free(scamper_sourcetask_t *st)
{
  scamper_source_t *source = st->source;

  sources_assert();

  if(st->node != NULL)
    dlist_node_pop(source->tasks, st->node);
  if(st->idnode != NULL)
    splaytree_remove_node(source->idtree, st->idnode);
  scamper_source_free(st->source);
  free(st);

  if(scamper_source_isfinished(source) != 0)
    {
      if(source->cyclemon != NULL)
	{
	  assert(scamper_cyclemon_refcnt(source->cyclemon) == 1);
	  scamper_cyclemon_unuse(source->cyclemon);
	  source->cyclemon = NULL;
	}
      source_detach(source);
    }

  sources_assert();
  return;
}

int scamper_source_add_dup(scamper_source_t *source,
			   scamper_task_t *task, uint32_t id)
{
  scamper_sourcetask_t *st = NULL;
  if((st = sourcetask_alloc(source, task)) == NULL)
    return -1;
  st->id = id;
  scamper_task_setsourcetask(task, st);
  return 0;
}

/*
 * scamper_source_use
 *
 */
scamper_source_t *scamper_source_use(scamper_source_t *source)
{
  sources_assert();
  source->refcnt++;
  return source;
}

/*
 * scamper_source_abandon
 *
 */
void scamper_source_abandon(scamper_source_t *source)
{
  sources_assert();
  source_flush_tasks(source);
  source_flush_commands(source);
  source_detach(source);
  sources_assert();
  return;
}

/*
 * scamper_source_free
 *
 * the caller is giving up their reference to the source.  make a note
 * of that.  when the reference count reaches zero and the source is
 * finished, free it.
 */
void scamper_source_free(scamper_source_t *source)
{
  sources_assert();

  /*
   * if there are still references held to the source, or the source is not
   * finished yet, then we don't have to go further.
   */
  if(source_refcnt_dec(source) != 0)
    return;

  source_free(source);
  sources_assert();
  return;
}

/*
 * scamper_source_alloc
 *
 * create a new source based on the parameters supplied.  the source is
 * not put into rotation -- the caller has to call scamper_sources_add
 * for that to occur.
 */
scamper_source_t *scamper_source_alloc(const scamper_source_params_t *ssp)
{
  scamper_source_t *source = NULL;

  /* make sure the caller passes some details of the source to be created */
  if(ssp == NULL || ssp->name == NULL)
    {
      scamper_debug(__func__, "missing necessary parameters");
      goto err;
    }

  if((source = malloc_zero(sizeof(scamper_source_t))) == NULL)
    {
      printerror(__func__, "could not malloc source");
      goto err;
    }
  source->refcnt = 1;

  /* data parameter and associated callbacks */
  source->data        = ssp->data;
  source->take        = ssp->take;
  source->freedata    = ssp->freedata;
  source->isfinished  = ssp->isfinished;
  source->tostr       = ssp->tostr;

  source->list = scamper_list_alloc(ssp->list_id, ssp->name, ssp->descr,
	ssp->monitor == NULL ? scamper_option_monitorname_get() : ssp->monitor);
  if(source->list == NULL)
    {
      printerror(__func__, "could not alloc source->list");
      goto err;
    }

  if((source->commands = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc source->commands");
      goto err;
    }

  if((source->tasks = dlist_alloc()) == NULL)
    {
      printerror(__func__, "could not alloc source->tasks");
      goto err;
    }

  source->sof = scamper_outfile_use(ssp->sof);
  if(source_cycle(source, ssp->cycle_id) != 0)
    {
      goto err;
    }

  source->type     = ssp->type;
  source->priority = ssp->priority;
  source->id       = 1;

  return source;

 err:
  if(source != NULL)
    {
      if(source->list != NULL) scamper_list_free(source->list);
      if(source->cycle != NULL) scamper_cycle_free(source->cycle);
      if(source->commands != NULL) dlist_free(source->commands);
      if(source->tasks != NULL) dlist_free(source->tasks);
      free(source);
    }
  return NULL;
}

/*
 * scamper_sources_get
 *
 * given a name, return the matching source -- if one exists.
 */
scamper_source_t *scamper_sources_get(char *name)
{
  scamper_source_t findme;
  scamper_list_t   list;

  list.name   = name;
  findme.list = &list;

  return (scamper_source_t *)splaytree_find(source_tree, &findme);
}

/*
 * scamper_sources_isempty
 *
 * return to the caller if it is likely that the sources have more tasks
 * to return
 */
int scamper_sources_isempty()
{
  sources_assert();

  /*
   * if there are either active or blocked address list sources, the list
   * can't be empty
   */
  if((active   != NULL && clist_count(active)   > 0) ||
     (blocked  != NULL && dlist_count(blocked)  > 0) ||
     (finished != NULL && dlist_count(finished) > 0))
    {
      return 0;
    }

  return 1;
}

/*
 * scamper_sources_isready
 *
 * return to the caller if a source is ready to return a new task.
 */
int scamper_sources_isready(void)
{
  sources_assert();

  if(source_cur != NULL || dlist_count(finished) > 0)
    {
      return 1;
    }

  return 0;
}

/*
 * scamper_sources_empty
 *
 * flush all sources of commands; disconnect all sources.
 */
void scamper_sources_empty()
{
  scamper_source_t *source;

  sources_assert();

  /*
   * for each source, go through and empty the lists, close the files, and
   * leave the list of sources available to read from empty.
   */
  while((source = dlist_tail_item(blocked)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = clist_tail_item(active)) != NULL)
    {
      source_flush_commands(source);
      source_detach(source);
    }

  while((source = dlist_head_item(finished)) != NULL)
    {
      source_detach(source);
    }

  sources_assert();
  return;
}

/*
 * scamper_sources_foreach
 *
 * externally accessible function for iterating over the collection of sources
 * held by scamper.
 */
void scamper_sources_foreach(void *p, int (*func)(void *, scamper_source_t *))
{
  splaytree_inorder(source_tree, (splaytree_inorder_t)func, p);
  return;
}

/*
 * scamper_sources_gettask
 *
 * pick off the next task ready to be probed.
 */
int scamper_sources_gettask(scamper_task_t **task)
{
  scamper_source_t *source;
  command_t *command;

  sources_assert();

  while((source = dlist_head_item(finished)) != NULL)
    source_detach(source);

  /*
   * if the priority of the source was changed in between calls to this
   * function, then make sure the source's priority hasn't been lowered to
   * below how many tasks it has had allocated in this cycle
   */
  if(source_cur != NULL && source_cnt >= source_cur->priority)
    source_next();

  while((source = source_cur) != NULL)
    {
      assert(source->priority > 0);

      while((command = dlist_head_pop(source->commands)) != NULL)
	{
	  if(source->take != NULL)
	    source->take(source->data);

	  switch(command->type)
	    {
	    case COMMAND_PROBE:
	      if(command_probe_handle(source, command, task) != 0)
		goto err;
	      if(*task == NULL)
		continue;
	      source_cnt++;
	      goto done;

	    case COMMAND_TASK:
	      if(command_task_handle(source, command, task) != 0)
		goto err;
	      if(*task == NULL)
		continue;
	      source_cnt++;
	      goto done;

	    case COMMAND_CYCLE:
	      command_cycle_handle(source, command);
	      break;

	    default:
	      goto err;
	    }
	}

      /* the previous source could not supply a command */
      assert(dlist_count(source->commands) == 0);

      /*
       * if the source is not yet finished, put it on the blocked list;
       * otherwise, the source is detached.
       */
      if(scamper_source_isfinished(source) == 0)
	source_blocked_attach(source);
      else
	source_detach(source);
    }

  *task = NULL;

 done:
  sources_assert();
  return 0;

 err:
  sources_assert();
  return -1;
}

/*
 * scamper_sources_add
 *
 * add a new source into rotation; put it into the active list for now.
 */
int scamper_sources_add(scamper_source_t *source)
{
  char buf[512];

  assert(source != NULL);
  sources_assert();

  if(scamper_source_tostr(source, buf, sizeof(buf)) != NULL)
    scamper_debug(__func__, "%s", buf);

  /* a reference count is used when the source is in the tree */
  if((source->tree_node = splaytree_insert(source_tree, source)) == NULL)
    goto err;
  scamper_source_use(source);

  /* put the source in the active queue */
  if(source_active_attach(source) != 0)
    goto err;

  sources_assert();
  return 0;

 err:
  sources_assert();
  return -1;
}

/*
 * scamper_sources_init
 *
 *
 */
int scamper_sources_init(void)
{
  if((active = clist_alloc()) == NULL)
    return -1;

  if((blocked = dlist_alloc()) == NULL)
    return -1;

  if((finished = dlist_alloc()) == NULL)
    return -1;

  if((source_tree = splaytree_alloc((splaytree_cmp_t)source_cmp)) == NULL)
    return -1;

  return 0;
}

/*
 * scamper_sources_cleanup
 *
 *
 */
void scamper_sources_cleanup(void)
{
  int f, b, a;

  f = finished != NULL ? dlist_count(finished) : 0;
  b = blocked  != NULL ? dlist_count(blocked)  : 0;
  a = active   != NULL ? clist_count(active)   : 0;

  if(f != 0 || b != 0 || a != 0)
    scamper_debug(__func__, "finished %d, blocked %d, active %d", f, b, a);

  if(source_tree != NULL)
    {
      splaytree_free(source_tree, NULL);
      source_tree = NULL;
    }

  if(blocked != NULL)
    {
      dlist_free(blocked);
      blocked = NULL;
    }

  if(active != NULL)
    {
      clist_free(active);
      active = NULL;
    }

  if(finished != NULL)
    {
      dlist_free(finished);
      finished = NULL;
    }

  return;
}
