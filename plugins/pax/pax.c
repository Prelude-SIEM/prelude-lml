#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/sensor.h>
#include <libprelude/prelude-getopt.h>

#include "log-common.h"
#include "log.h"

#define PAX_INFO_URL "http://pageexec.virtualave.net/"

static plugin_log_t plugin;

static int is_enabled = 0;

// ------------------------------------------------------------------

// Common struct 

typedef struct _log_time {
	unsigned int hour;
	unsigned int minute;
	unsigned int sec;
} log_time_t;

typedef struct _log_date {
	char *month;
	unsigned int day;
} log_date_t;

typedef struct _log_common {
	log_date_t date;
	log_time_t time;
	char *hostname;
	char *facility;
} log_common_t;

// end of common struct

// ------------------------------------------------------------------

// Message types

enum msg_types {
	wtf_msg_type,
	tt_msg_type,
	dos_msg_type,
	dtlb_msg_type
};

// ------------------------------------------------------------------

// struct WTF

typedef struct _log_pax_wtf {
	log_common_t *common_info;
	char *comm;
	unsigned int pid;
	unsigned long fault_counter;
} log_pax_wtf_t;

// ------------------------------------------------------------------

// struct terminating task

typedef struct _log_pax_terminating_task {
	log_common_t *common_info;
	char *path;
	char *comm;
	unsigned int pid;
	unsigned int uid;
	unsigned int euid;
	unsigned long eip;
	unsigned long esp;
} log_pax_terminating_task_t;

// end of struct terminating task

// ------------------------------------------------------------------

// struct DOS

typedef struct _log_pax_dos {
	log_common_t *common_info;
	char *comm;
	unsigned int pid;
	unsigned int uid;
	unsigned long eip;
	unsigned long esp;
} log_pax_dos_t;

// end of struct DOS

// ------------------------------------------------------------------

// struct DTLB_TRASHING

typedef struct _log_pax_dtlb_trashing {
	log_common_t *common_info;
	unsigned long counter;
	char *comm;
	unsigned int pid;
	unsigned long eip;
	unsigned long esp;
	unsigned long addr;
} log_pax_dtlb_trashing_t;

// ------------------------------------------------------------------

// fill the common struct and returns it

static log_common_t *fill_common(const char *log)
{
	unsigned int temp_size = (unsigned int) (strlen(log) / 3 + 1);
	log_common_t *common =
	    (log_common_t *) malloc(sizeof(log_common_t));

	common->date.month = (char *) malloc(temp_size * sizeof(char));
	common->hostname = (char *) malloc(temp_size * sizeof(char));
	common->facility = (char *) malloc(temp_size * sizeof(char));

	sscanf(log, "%s %u %u:%u:%u %s %s",
	       common->date.month, &common->date.day, &common->time.hour,
	       &common->time.minute, &common->time.sec, common->hostname,
	       common->facility);

	common->date.month =
	    (char *) realloc(common->date.month,
			     strlen(common->date.month) + 1);
	common->hostname =
	    (char *) realloc(common->hostname,
			     strlen(common->hostname) + 1);
	common->facility =
	    (char *) realloc(common->facility,
			     strlen(common->facility) + 1);

	return common;
}

// ------------------------------------------------------------------

// fill a log_pax_wtf_t structure

/* 
 * Will get the information printk'ed by PaX in:
 * printk(KERN_ERR "PAX: wtf: %s:%d, %ld\n", 
 * tsk->comm, tsk->pid, tsk->thread.pax_faults.count); 
 */

static int fill_wtf(log_pax_wtf_t * wtf, const char *log)
{
	int filled;

	wtf->comm = (char *) malloc(strlen(log) * sizeof(char));

	filled = sscanf(log, " %[^:]:%d, %ld",
			wtf->comm, &wtf->pid, &wtf->fault_counter);
	wtf->comm =
	    realloc(wtf->comm, (strlen(wtf->comm) + 1) * sizeof(char));
	return filled;
}

// ------------------------------------------------------------------

// fill a log_pax_terminanting_tast_t structure

/* 
 * Will get the information printk'ed by PaX in:
 * KERN_ERR "PAX: terminating task: %s(%s):%d, uid/euid: %u/%u, EIP: %08lX, ESP: %08lX\n", 
 * path, tsk->comm, tsk->pid, tsk->uid, tsk->euid, regs->eip, regs->esp);
 */

static int
fill_terminating_task(log_pax_terminating_task_t * tt, const char *log)
{
	int filled;

	tt->path = (char *) malloc(strlen(log) * sizeof(char));
	tt->comm = (char *) malloc(strlen(log) * sizeof(char));

	filled =
	    sscanf(log,
		   " %[^(](%[^)]):%d, uid/euid: %u/%u, EIP: %08lX, ESP: %08lX",
		   tt->path, tt->comm, &tt->pid, &tt->uid, &tt->euid,
		   &tt->eip, &tt->esp);

	tt->path =
	    realloc(tt->path, (strlen(tt->path) + 1) * sizeof(char));
	tt->comm =
	    realloc(tt->comm, (strlen(tt->comm) + 1) * sizeof(char));
	return filled;
}


// ------------------------------------------------------------------

// fill a log_pax_dos_t structure

/* 
 * Will get the information printk'ed by PaX in:
 * printk(KERN_ERR "PAX: preventing DoS: %s:%d, EIP: %08lX, ESP: %08lX\n", 
 * tsk->comm, tsk->pid, regs->eip, regs->esp);
 */

static int fill_dos(log_pax_dos_t * dos, const char *log)
{
	int filled;

	dos->comm = (char *) malloc(strlen(log) * sizeof(char));

	filled = sscanf(log, " %[^:]:%d, EIP: %08lX, ESP: %08lX",
			dos->comm, &dos->pid, &dos->eip, &dos->esp);

	dos->comm =
	    realloc(dos->comm, (strlen(dos->comm) + 1) * sizeof(char));
	return filled;
}

// ------------------------------------------------------------------

// fill a log_pax_dtlb_trashing_t structure

/* 
 * Will get the information printk'ed by PaX in:
 * printk(KERN_ERR "PAX: DTLB trashing, level %ld: %s:%d,"
 * "EIP: %08lX, ESP: %08lX, cr2: %08lX\n",
 * tsk->thread.pax_faults.count - (PAX_SPIN_COUNT+1), 
 * tsk->comm, tsk->pid, regs->eip, regs->esp, address);
 */

static int
fill_dtlb_trashing(log_pax_dtlb_trashing_t * dtlb, const char *log)
{
	int filled;

	dtlb->comm = (char *) malloc(strlen(log) * sizeof(char));

	filled =
	    sscanf(log,
		   "  %ld: %[^:]:%d,EIP: %08lX, ESP: %08lX, cr2: %08lX",
		   &dtlb->counter, dtlb->comm, &dtlb->pid, &dtlb->eip,
		   &dtlb->esp, &dtlb->addr);

	dtlb->comm =
	    realloc(dtlb->comm, (strlen(dtlb->comm) + 1) * sizeof(char));
	return filled;
}

// ------------------------------------------------------------------

// auxiliary idmef functions

static int
fill_target(idmef_target_t * target, int type,
	    unsigned long log_pax_struct)
{
	idmef_node_t *node = idmef_target_node_new(target);
	idmef_process_t *process = idmef_target_process_new(target);
	idmef_user_t *user = NULL;
	idmef_userid_t *userid;

	if (!(node && process))
		return -1;

	switch (type) {
	case (wtf_msg_type):
		idmef_string_set(&process->name,
				 ((log_pax_wtf_t *) log_pax_struct)->comm);
		process->pid = ((log_pax_wtf_t *) log_pax_struct)->pid;
		idmef_string_set(&node->name,
				 ((log_pax_wtf_t *) log_pax_struct)->
				 common_info->hostname);
		break;

	case (tt_msg_type):
		user = idmef_target_user_new(target);

		idmef_string_set(&process->path,
				 ((log_pax_terminating_task_t *)
				  log_pax_struct)->path);
		idmef_string_set(&process->name,
				 ((log_pax_terminating_task_t *)
				  log_pax_struct)->comm);
		process->pid =
		    ((log_pax_terminating_task_t *) log_pax_struct)->pid;
		idmef_string_set(&node->name,
				 ((log_pax_terminating_task_t *)
				  log_pax_struct)->common_info->hostname);

		if (user && (userid = idmef_user_userid_new(user))) {
			userid->type = current_user;
			userid->number =
			    ((log_pax_terminating_task_t *)
			     log_pax_struct)->uid;

			if ((userid = idmef_user_userid_new(user))) {
				userid->type = user_privs;
				userid->number =
				    ((log_pax_terminating_task_t *)
				     log_pax_struct)->euid;
			}
		}
		break;

	case (dos_msg_type):
		idmef_string_set(&process->name,
				 ((log_pax_dos_t *) log_pax_struct)->comm);
		process->pid = ((log_pax_dos_t *) log_pax_struct)->pid;
		idmef_string_set(&node->name,
				 ((log_pax_dos_t *) log_pax_struct)->
				 common_info->hostname);

		if (user && (userid = idmef_user_userid_new(user))) {
			userid->type = current_user;
			userid->number =
			    ((log_pax_dos_t *) log_pax_struct)->uid;
		}
		break;

	case (dtlb_msg_type):
		idmef_string_set(&process->name,
				 ((log_pax_dtlb_trashing_t *)
				  log_pax_struct)->comm);
		process->pid =
		    ((log_pax_dtlb_trashing_t *) log_pax_struct)->pid;
		idmef_string_set(&node->name,
				 ((log_pax_dtlb_trashing_t *)
				  log_pax_struct)->common_info->hostname);
		break;

	}

	return 0;
}

// ------------------------------------------------------------------

// global handling of the PaX log

static void pax_log_processing(const log_container_t * log)
{
	log_common_t *log_c = fill_common(log->log);
	char *tmp = (char *) malloc((strlen(log->log) + 1) * sizeof(char));
	idmef_message_t *message = idmef_message_new();
	idmef_alert_t *alert;
	prelude_msgbuf_t *msgbuf;
	char *tmp_save = tmp;

	if (!message)
		return -1;

	msgbuf = prelude_msgbuf_new(0);
	if (!msgbuf)
		goto errbuf;

	/* Initialize the idmef structures */
	idmef_alert_new(message);
	alert = message->message.alert;

	/*
	   idmef_alert_detect_time_new(alert);
	   idmef_alert_analyzer_time_new(alert);
	 */


	/* Verify it is a PAX log, ie if it is formatted as expected */
	if ((tmp = strstr(log->log, "PAX: "))) {
		int ret = 0;
		idmef_assessment_t *assessment;
		idmef_action_t *action;
		idmef_classification_t *classification;
		idmef_additional_data_t *additional;
		idmef_target_t *target;

		tmp = tmp + 5;	/* tmp now points after 'PAX: ' */

		/* 
		 * Analyzer section: genral information; 
		 * no node or process class is provided  
		 */
		idmef_string_set_constant(&alert->analyzer.model,
					  "PaX Linux Kernel patch");
		idmef_string_set_constant(&alert->analyzer.class,
					  "Non-executable Memory Page Violation Detection ");
		idmef_string_set_constant(&alert->analyzer.ostype,
					  "Linux");

		/* 
		 * Assessment section: bases are set here, more details further
		 * Impact, Action, Confidence
		 */
		idmef_alert_assessment_new(alert);
		assessment = alert->assessment;

		idmef_assessment_impact_new(assessment);
		assessment->impact->severity = impact_medium;
		assessment->impact->completion = failed;
		assessment->impact->type = other;

		action = idmef_assessment_action_new(assessment);
		if (!action)
			goto err;
		action->category = notification_sent;

		idmef_assessment_confidence_new(assessment);
		assessment->confidence->rating = high;

		/*
		 * Classification section:
		 * origin unknown by default, name specified further, url : cf sigmund
		 */
		classification = idmef_alert_classification_new(alert);
		if (!classification)
			goto err;
		idmef_string_set_constant(&classification->url,
					  PAX_INFO_URL);


		/*
		 * Additional data section: contains the log message ?
		 */
		additional = idmef_alert_additional_data_new(alert);
		if (!additional)
			goto err;
		additional->type = string;
		idmef_string_set_constant(&additional->meaning,
					  "PaX log message");
		idmef_string_set(&additional->data, log->log);

		/*
		 * Target section: the target is the machine using PaX
		 * We have information on: 
		 *         - the node: always
		 *         - the process: always
		 *         - the user: only in terminating task and dos 
		 * user: when euid is not uid we'll consider it's an attempt to
		 * to become the user corresponding to euid
		 */
		target = idmef_alert_target_new(alert);
		if (!target)
			goto err;
		/* test in the subcases if we have a hostname or an addr */

		/* 
		 * Try to do sthg general to fill what we can always fill
		 * process or node info for instance, why not user & userid ?
		 */

		/* Which kind of PaX msg are we dealing with ? */
		if (strncmp(tmp, "wtf: ", 5) == 0) {
			log_pax_wtf_t wtf;
			wtf.common_info = log_c;

			tmp = tmp + 5;
			ret = fill_wtf(&wtf, tmp);

			if (ret != 3)
				goto err;

			fill_target(target, wtf_msg_type,
				    (unsigned long) &wtf);
			goto msg;
		}

		if (strncmp(tmp, "terminating task: ", 18) == 0) {
			log_pax_terminating_task_t tt;
			tt.common_info = log_c;

			tmp = tmp + 18;
			ret = fill_terminating_task(&tt, tmp);

			if (ret != 7)
				goto err;

			fill_target(target, tt_msg_type,
				    (unsigned long) &tt);
			idmef_string_set_constant(&assessment->impact->
						  description,
						  "Code execution in non-executable memory page detected and avoided by PaX");
			idmef_string_set_constant(&action->description,
						  "Process killed");
			idmef_string_set_constant(&classification->name,
						  "Forbidden Code Execution Attempt");
			if (tt.uid != tt.euid) {
				if (tt.euid == 0)
					assessment->impact->type = admin;
				else
					assessment->impact->type = user;
			}

			goto msg;
		}

		if (strncmp(tmp, "preventing DoS: ", 16) == 0) {
			log_pax_dos_t pdos;
			pdos.common_info = log_c;

			tmp = tmp + 16;
			ret = fill_dos(&pdos, tmp);

			if (ret != 4)
				goto err;

			fill_target(target, dos_msg_type,
				    (unsigned long) &pdos);
			assessment->impact->type = dos;
			idmef_string_set_constant(&assessment->impact->
						  description,
						  "DoS Attempt detected and avoided by PaX");
			idmef_string_set_constant(&action->description,
						  "Process killed");
			idmef_string_set_constant(&classification->name,
						  "DoS Attempt against the Kernel memory manager");

			goto msg;
		}

		if (strncmp(tmp, " DTLB trashing, level ", 22) == 0) {
			log_pax_dtlb_trashing_t dtlb;
			dtlb.common_info = log_c;

			tmp = tmp + 22;
			ret = fill_dtlb_trashing(&dtlb, tmp);

			if (ret != 22)
				goto err;

			fill_target(target, dtlb_msg_type,
				    (unsigned long) &dtlb);

			goto msg;
		}
	}

      msg:
	idmef_msg_send(msgbuf, message, PRELUDE_MSG_PRIORITY_MID);
	idmef_message_free(message);
	prelude_msgbuf_close(msgbuf);
	if (tmp_save)
		free(tmp_save);
	if (log_c)
		free(log_c);
	return;

      err:
	prelude_msgbuf_close(msgbuf);
      errbuf:
	idmef_message_free(message);
	if (tmp_save)
		free(tmp_save);
	if (log_c)
		free(log_c);
	return;
}

static int set_pax_state(const char *optarg)
{
	int ret;

	if (is_enabled == 1) {
		ret = plugin_unsubscribe((plugin_generic_t *) & plugin);
		if (ret < 0)
			return prelude_option_error;

		is_enabled = 0;
	} else {
		ret = plugin_subscribe((plugin_generic_t *) & plugin);
		if (ret < 0)
			return prelude_option_error;

		is_enabled = 1;
	}

	return prelude_option_success;
}

static int get_pax_state(char *buf, size_t size)
{
	snprintf(buf, size, "%s",
		 (is_enabled == 1) ? "enabled" : "disabled");
	return prelude_option_success;
}

plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

	opt = prelude_option_add(NULL, CLI_HOOK | CFG_HOOK, 0, "paxmod",
				 "Set PaxMod plugin option", no_argument,
				 set_pax_state, get_pax_state);

	plugin_set_name(&plugin, "Paxmod");
	plugin_set_author(&plugin,
			  "Vincent Glaume & Pierre-Alain Fayolle");
	plugin_set_contact(&plugin,
			   "glaume@enseirb.fr, fayolle@enseirb.fr");
	plugin_set_desc(&plugin, "Pax machin machin.");
	plugin_set_running_func(&plugin, pax_log_processing);

	return (plugin_generic_t *) & plugin;
}
