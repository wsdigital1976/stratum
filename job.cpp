
#include "stratum.h"

#define MAX_JOBAGE 120;

#define RETURN_ON_CONDITION(condition, ret) \
	if(condition) \
	{ \
		return ret; \
	}

static bool job_assign_client(YAAMP_JOB *job, YAAMP_CLIENT *client, double maxhash)
{
	RETURN_ON_CONDITION(client->deleted, true);
	RETURN_ON_CONDITION(client->jobid_next, true);
	RETURN_ON_CONDITION(job->coind->mining_disabled, true);
	RETURN_ON_CONDITION(client->jobid_locked && client->jobid_locked != job->id, true);
	RETURN_ON_CONDITION(client_find_job_history(client, job->id), true);
	RETURN_ON_CONDITION(maxhash > 0 && job->speed + client->speed > maxhash, true);

	bool specific_mining = (client->coins_mining_list.size() > 0 );
	bool coin_to_mine = (std::find(client->coins_mining_list.begin(), client->coins_mining_list.end(), job->coind->symbol) != client->coins_mining_list.end()) ||
						(std::find(client->coins_mining_list.begin(), client->coins_mining_list.end(), job->coind->symbol2) != client->coins_mining_list.end());
	bool coin_to_ignore = (std::find(client->coins_ignore_list.begin(), client->coins_ignore_list.end(), job->coind->symbol) != client->coins_ignore_list.end()) ||
						  (std::find(client->coins_ignore_list.begin(), client->coins_ignore_list.end(), job->coind->symbol2) != client->coins_ignore_list.end());

	if(!g_autoexchange && maxhash >= 0. && client->coinid != job->coind->id) {
		//debuglog("prevent client %c on %s, not the right coin\n",
		//	client->username[0], job->coind->symbol);
		return true;
	}

	if (coin_to_ignore) {
		return true;
	}

	if ((!job->coind->auto_exchange) && (!coin_to_mine)) {
		return true;
	}

	if ( maxhash >= 0. ) {
		if (( specific_mining ) && (!coin_to_mine)) return true;
	}

	if(job->remote)
	{
		YAAMP_REMOTE *remote = job->remote;

		if(g_stratum_reconnect)
			{RETURN_ON_CONDITION(!client->extranonce_subscribe && !client->reconnectable, true);}
		else
			{RETURN_ON_CONDITION(!client->extranonce_subscribe, true);}

		RETURN_ON_CONDITION(client->reconnecting, true);
		RETURN_ON_CONDITION(job->count >= YAAMP_JOB_MAXSUBIDS, false);
//		RETURN_ON_CONDITION(client->difficulty_actual > remote->difficulty_actual, false);

		double difficulty_remote = client->difficulty_remote;
		if(remote->difficulty_actual < client->difficulty_actual)
		{
			RETURN_ON_CONDITION(client->difficulty_fixed, true);
			RETURN_ON_CONDITION(remote->difficulty_actual*4 < client->difficulty_actual, true);

			difficulty_remote = remote->difficulty_actual;
		}

		else if(remote->difficulty_actual > client->difficulty_actual)
			difficulty_remote = 0;

		if(remote->nonce2size == 2)
		{
			RETURN_ON_CONDITION(job->count > 0, false);

			strcpy(client->extranonce1, remote->nonce1);
			client->extranonce2size = 2;
		}

		else if(job->id != client->jobid_sent)
		{
			if(!job->remote_subids[client->extranonce1_id])
				job->remote_subids[client->extranonce1_id] = true;

			else
			{
				int i=0;
				for(; i<YAAMP_JOB_MAXSUBIDS; i++) if(!job->remote_subids[i])
				{
					job->remote_subids[i] = true;
					client->extranonce1_id = i;

					break;
				}

				RETURN_ON_CONDITION(i == YAAMP_JOB_MAXSUBIDS, false);
			}

			sprintf(client->extranonce1, "%s%02x", remote->nonce1, client->extranonce1_id);
			client->extranonce2size = remote->nonce2size-1;
			client->difficulty_remote = difficulty_remote;
		}

		client->jobid_locked = job->id;
	}

	else
	{
		strcpy(client->extranonce1, client->extranonce1_default);
		client->extranonce2size = client->extranonce2size_default;

		// decred uses an extradata field in block header, 2 first uint32 are set by the miner
		if (g_current_algo->name && !strcmp(g_current_algo->name,"decred")) {
			memset(client->extranonce1, '0', sizeof(client->extranonce1));
			memcpy(&client->extranonce1[16], client->extranonce1_default, 8);
			client->extranonce1[24] = '\0';
		}

		client->difficulty_remote = 0;
		client->jobid_locked = 0;
	}

	client->jobid_next = job->id;

	job->speed += client->speed;
	job->count++;

//	debuglog(" assign %x, %f, %d, %s\n", job->id, client->speed, client->reconnecting, client->sock->ip);
	if(strcmp(client->extranonce1, client->extranonce1_last) || client->extranonce2size != client->extranonce2size_last)
	{
//		debuglog("new nonce %x %s %s\n", job->id, client->extranonce1_last, client->extranonce1);
		if(!client->extranonce_subscribe)
		{
			strcpy(client->extranonce1_reconnect, client->extranonce1);
			client->extranonce2size_reconnect = client->extranonce2size;

			strcpy(client->extranonce1, client->extranonce1_default);
			client->extranonce2size = client->extranonce2size_default;

			client->reconnecting = true;
			client->lock_count++;
			client->unlock = true;
			client->jobid_sent = client->jobid_next;

			socket_send(client->sock, "{\"id\":null,\"method\":\"client.reconnect\",\"params\":[\"%s\",%d,0]}\n", g_tcp_server, g_tcp_port);
		}

		else
		{
			strcpy(client->extranonce1_last, client->extranonce1);
			client->extranonce2size_last = client->extranonce2size;

			socket_send(client->sock, "{\"id\":null,\"method\":\"mining.set_extranonce\",\"params\":[\"%s\",%d]}\n",
				client->extranonce1, client->extranonce2size);
		}
	}

	return true;
}

void job_assign_clients(YAAMP_JOB *job, double maxhash)
{
	if (!job) return;

	job->speed = 0;
	job->count = 0;

	g_list_client.Enter();

	// pass0 locked
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_locked && client->jobid_locked != job->id) continue;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	// pass1 sent
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->jobid_sent != job->id) continue;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	// pass2 extranonce_subscribe
	if(job->remote)	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(!client->extranonce_subscribe) continue;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	// pass3 the rest
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;

		bool b = job_assign_client(job, client, maxhash);
		if(!b) break;
	}

	g_list_client.Leave();
}

void job_assign_clients_left(double factor)
{
	bool b;
	for(CLI li = g_list_coind.first; li; li = li->next)
	{
		if(!job_has_free_client()) return;

		YAAMP_COIND *coind = (YAAMP_COIND *)li->data;
		if(!coind_can_mine(coind)) continue;
		if(!coind->job) continue;

		double nethash = coind_nethash(coind);
		g_list_client.Enter();

		for(CLI li = g_list_client.first; li; li = li->next)
		{
			YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
			bool coin_to_mine = (std::find(client->coins_mining_list.begin(), client->coins_mining_list.end(), coind->symbol) != client->coins_mining_list.end()) ||
								(std::find(client->coins_mining_list.begin(), client->coins_mining_list.end(), coind->symbol2) != client->coins_mining_list.end());
			bool coin_to_ignore = (std::find(client->coins_ignore_list.begin(), client->coins_ignore_list.end(), coind->symbol) != client->coins_ignore_list.end()) ||
								  (std::find(client->coins_ignore_list.begin(), client->coins_ignore_list.end(), coind->symbol2) != client->coins_ignore_list.end());

			if (!g_autoexchange) {
				if (client->coinid == coind->id)
					factor = 100.;
				else
					factor = 0.;
			}
			else if ((!(coind->auto_exchange)) && (!coin_to_mine)) {
				factor = 0.;
			}

			if (coin_to_ignore) {
				factor = 0.;
			}

			//debuglog("%s %s factor %f nethash %.3f\n", coind->symbol, client->username, factor, nethash);

			if (factor > 0.) {
				b = job_assign_client(coind->job, client, nethash*factor);
				if(!b) break;
			}
		}

		g_list_client.Leave();
	}
}

void job_check_status() {

	time_t tmpjobage;

	g_list_job.Enter();

	for(CLI li = g_list_job.first; li; li = li->next) {
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if (!job) continue;

		/*
		debuglog("job %i from coin %s templ->height %i coin->height %i status %i isdelete %i\n",
				job->id,
				(job->coind)?job->coind->symbol:"NULL",
				(job->templ)?job->templ->height:0,
				(job->coind)?job->coind->height:0,
				job->status,
				job->deleted);
*/
		// check status
		if (job->status != JOB_STATUS_WAITING) { continue; }

		// todo: add timeout for jobs
		if (!job->templ) { job->deleted = true; continue; }
		if (!job->coind) { job->deleted = true; continue; }

		tmpjobage = time(NULL) - MAX_JOBAGE;
		if (job->jobage <= tmpjobage) {
//			debuglog("delete timeouted job %i from coin %s height %i\n",
//					job->id, job->coind->symbol, job->templ->height);
			job->deleted = true;
			continue;
		}


		if (job->templ->height <= job->coind->height) {
//			debuglog("delete job %i from coin %s height %i\n",
//					job->id, job->coind->symbol, job->templ->height);
			job->deleted = true;
			continue;
		}

	}
	g_list_job.Leave();
}
////////////////////////////////////////////////////////////////////////

pthread_mutex_t g_job_mutex;
pthread_cond_t g_job_cond;

void *job_thread(void *p)
{
	CommonLock(&g_job_mutex);
	while(!g_exiting)
	{
		job_update();
		pthread_cond_wait(&g_job_cond, &g_job_mutex);
	}
}

void job_init()
{
	pthread_mutex_init(&g_job_mutex, 0);
	pthread_cond_init(&g_job_cond, 0);

	pthread_t thread3;
	pthread_create(&thread3, NULL, job_thread, NULL);
}

void job_signal()
{
	CommonLock(&g_job_mutex);
	pthread_cond_signal(&g_job_cond);
	CommonUnlock(&g_job_mutex);
}

void job_update()
{
//	debuglog("job_update()\n");
	job_reset_clients();

	//////////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_job.Enter();
	job_sort();

	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_assign_clients(job, job->maxspeed);
		job_unlock_clients(job);

		if(!job_has_free_client()) break;
	}

	job_unlock_clients();
	g_list_job.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_coind.Enter();
	coind_sort();

	job_assign_clients_left(1);
	job_assign_clients_left(1);
	job_assign_clients_left(-1);

	g_list_coind.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

	g_list_client.Enter();
	for(CLI li = g_list_client.first; li; li = li->next)
	{
		YAAMP_CLIENT *client = (YAAMP_CLIENT *)li->data;
		if(client->deleted) continue;
		if(client->jobid_next) continue;

		debuglog("clients with no job\n");
		g_current_algo->overflow = true;

		if(!g_list_coind.first) break;

		// here: todo: choose first can mine

		YAAMP_COIND *coind = (YAAMP_COIND *)g_list_coind.first->data;
		if(!coind) break;

		job_reset_clients(coind->job);
		coind_create_job(coind, true);
		job_assign_clients(coind->job, -1);

		break;
	}

	g_list_client.Leave();

	////////////////////////////////////////////////////////////////////////////////////////////////

//	usleep(100*YAAMP_MS);

//	int ready = 0;
//	debuglog("job_update\n");

	g_list_job.Enter();
	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if(!job_can_mine(job)) continue;

		job_broadcast(job);
//		ready++;
	}

//	debuglog("job_update %d / %d jobs\n", ready, g_list_job.count);
	g_list_job.Leave();

}

void job_log_statistic()
{
	int count_locked_deleted = 0;
	g_list_job.Enter();

	for(CLI li = g_list_job.first; li; li = li->next)
	{
		YAAMP_JOB *job = (YAAMP_JOB *)li->data;
		if (!job) continue;

		if ((job->deleted) && (job->lock_count)) {
			count_locked_deleted++;
			job->lock_count = 0;
		}
	}

	if (count_locked_deleted > 0)
		debuglog("job_log_statistic %d orphan jobs\n", count_locked_deleted);
	g_list_job.Leave();

}
