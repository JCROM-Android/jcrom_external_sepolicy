#include <ctype.h>
#include <errno.h>
#include <search.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sepol/context_record.h>
#include <sepol/sepol.h>

/**
 * Tool for validating property_contexts file
 * @author
 *  William Roberts <w.roberts@sta.samsung.com>
 *
 * @note
 * 	The error handling this code does, does not free anything. All
 * 	error's are fatal and the program just exits. Also, even under
 * 	a normal exit, the program is does not make any attempt to free
 * 	resources, since it is just terminating. However, runtime
 * 	allocations should be freed based on normal logic, ie
 * 	when updates to the hash table occur do to a replace.
 */


#define TABLE_SIZE 4096

static int logging_verbose = 0;

#define log_set_verbose() do { logging_verbose = 1; log_info("Enabling verbose\n"); } while(0)
#define log_error(fmt, ...) log_msg(stderr, "Error: ", fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_msg(stderr, "Warning: ", fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) if (logging_verbose ) { log_msg(stdout, "Info: ", fmt, ##__VA_ARGS__); }

typedef struct prop_con_entry prop_con_entry;
typedef struct prop_list_entry prop_list_entry;
typedef struct sepolicy sepolicy;
typedef struct file_info file_info;
typedef struct linked_list linked_list;

struct linked_list {
	prop_list_entry *head;
	prop_list_entry *tail;
};

struct file_info {
	char *name;
	FILE *fp;
};

struct sepolicy {

	file_info file;
	sepol_policydb_t *db;
	sepol_policy_file_t *pf;
	sepol_handle_t *handle;
};

struct prop_con_entry {

	char *property;
	char *context;
	unsigned int lineeno;
};

struct prop_list_entry {

	prop_list_entry *next;
	prop_con_entry data;
};

/* Internal interface */
static void log_msg(FILE *out, const char *prefix, const char *fmt, ...);
static void prop_list_add(linked_list *l, prop_list_entry *pce);
static void usage(char *name);
static void print(file_info *out, linked_list *ll);
static void parse(sepolicy *pol, file_info *pc, linked_list *ll, bool override);

int main(int argc, char *argv[]) {

	char c;
	bool override = false;

	sepolicy sepolicy_file;
	file_info prop_con_file;
	linked_list ll;
	file_info output_file = {
			.name = "stdout",
			.fp = stdout
	};

	memset(&ll, 0, sizeof(ll));
	memset(&sepolicy_file, 0, sizeof(sepolicy_file));
	memset(&prop_con_file, 0, sizeof(prop_con_file));

	while ((c = getopt (argc, argv, "fvo:p:")) != -1) {
		switch (c) {
		case 'o':
			output_file.name = optarg;
		break;
		case 'p':
			sepolicy_file.file.name = optarg;
		break;
		case 'f':
			override = true;
		break;
		case 'v':
			log_set_verbose();
		break;
		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		/* No Break */
		}
	}

	if (argc - optind != 1) {
		log_error("Expected a file_contexts path as an argument,"
				" got %d arguments!\n", argc-optind);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	prop_con_file.name = argv[optind];

	if(strcmp(output_file.name, "stdout")) {
		output_file.fp = fopen(output_file.name, "w+");
		if (!output_file.fp) {
			log_error("Could not open output file %s error: %s\n",
					output_file.name, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if(sepolicy_file.file.name) {
		sepolicy_file.file.fp = fopen(sepolicy_file.file.name, "rb");
		if (!sepolicy_file.file.fp) {
			log_error("Could not open sepolicy file %s error: %s\n",
					sepolicy_file.file.name, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	prop_con_file.fp = fopen(prop_con_file.name, "r");
	if (!prop_con_file.fp) {
		log_error("Could not open property_context file %s error: %s\n",
				output_file.name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (hcreate(TABLE_SIZE) < 0) {
		log_error("Could not create hashtable, error: %s\n",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(sepolicy_file.file.name) {
		sepolicy_file.handle = sepol_handle_create();
		if (!sepolicy_file.handle) {
			log_error("Could not create sepolicy handle, error: %s\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (sepol_policydb_create(&sepolicy_file.db) < 0) {
			log_error("Could not create sepolicy db, error: %s\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (sepol_policy_file_create(&sepolicy_file.pf) < 0) {
			log_error("Could not create sepolicy file, error: %s\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}

		sepol_policy_file_set_fp(sepolicy_file.pf, sepolicy_file.file.fp);
		sepol_policy_file_set_handle(sepolicy_file.pf, sepolicy_file.handle);

		if (sepol_policydb_read(sepolicy_file.db, sepolicy_file.pf) < 0) {
			log_error("Could not load sepolicy db, error: %s\n",
					strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	parse(&sepolicy_file, &prop_con_file, &ll, override);
	print(&output_file, &ll);
	return 0;

}

/**
 * Outputs a logging message
 * @param out
 *  The output file to print too
 * @param prefix
 *  The prefix to use
 * @param fmt
 *  fmt specifier to use
 */
static void log_msg(FILE *out, const char *prefix, const char *fmt, ...) {
	fprintf(out, "%s", prefix);
	va_list args;
	va_start(args, fmt);
	vfprintf(out, fmt, args);
	va_end(args);
}

/**
 * Adds to a linked list
 * @param l
 *  The linked list to add too
 * @param pce
 *  The element to add
 */
static void prop_list_add(linked_list *l, prop_list_entry *pce) {

	if(l) {

		pce->next = NULL;

		if(!l->head) {
			l->head = pce;
			l->tail = pce;
		}
		else {
			l->tail->next = pce;
			l->tail = pce;
		}
	}
	return;
}

/**
 * Prints the usage of the program
 * @param name
 *  The name of the program, typically argv[0]
 */
static void usage(char *name) {
	printf("\n\n%s [OPTIONS] <FILE>\n"
			"Parses a property_contexts file, given by argument [FILE] and checks for syntax errors.\n"
			"If the -p option is specified it also checks the selinux contexts against the specified\n"
			"policy file.\n"
			"Options\n"
			"-p [FILE] Policy file\n"
			"-o [FILE] output file\n"
			"-f force, override previous declarations\n"
			, name);
}

/**
 * Prints a linked list to a file
 * @param out
 *  The output file to print to
 * @param ll
 *  The linked list to print
 */
static void print(file_info *out, linked_list *ll) {

	prop_list_entry *cursor;

	if (ll && ll->head) {

		cursor = ll->head;

		while(cursor) {
			fprintf(out->fp, "%s\t%s\n", cursor->data.property, cursor->data.context);
			cursor = cursor->next;
		}
	}
	return;
}

/**
 * Parse the property contexts file, validate against a sepolicy, and possibly
 * override existing entries.
 *
 * @param pol
 *  The policy to verify contexts against
 * @param pc
 *  The property contexts file to parse
 * @param ll
 *  The linked list to append entries too. This can be NULL.
 * @param override
 *  A flag indicating whether or not new entries override old entries. False
 *  means that if a duplicate entry is found, it reports an error.
 */
static void parse(sepolicy *pol, file_info *pc, linked_list *ll, bool override) {

	char *p;
	char *tmp;
	char *token;
	char *tmp_prop;
	char *tmp_context;
	char buf[BUFSIZ];
	unsigned int item_cnt;

	ENTRY *e;
	ENTRY item;
	size_t len;
	prop_list_entry *t;
	prop_list_entry *pce;
	sepol_context_t *tmp_con;

	unsigned int lineno = 0;

	while (1) {

		lineno++;

		tmp = fgets(buf, BUFSIZ, pc->fp);
		if(!tmp) {
			if(ferror(pc->fp)) {
				log_error("An error occurred reading the property contexts file!\n");
				exit(EXIT_FAILURE);
			}
			/* EOF */
			break;
		}

		/* Prep the line */
		len = strlen(tmp);

		/* Strip trailing newline */
		if (tmp[len - 1] == '\n') {
			tmp[len - 1] = '\0';
		}

		p = tmp;

		/* Strip whitespace */
		while (isspace(*p)) {
			p++;
		}

		/* If it was an empty line or comment, process */
		if (*p == '#' || *p == '\0') {
			continue;
		}

		/* Process tokens */
		item_cnt = 0;
		tmp_context = tmp_prop = NULL;
		while ((token = strtok(p, " \t"))) {

			if(item_cnt == 0) {
				tmp_prop = token;
			}
			else if(item_cnt == 1) {
				tmp_context = token;
			}
			else {
				log_error("Unexpected token %s found on line %u in file %s\n",
						token, lineno, pc->name);
				exit(EXIT_FAILURE);
			}
			item_cnt++;
			p = NULL;

		} /* Done processing tokens */

		/* Check to make sure we found all tokens */
		if (!(tmp_prop && tmp_context)) {
			log_error("Did not find all tokens on line %u in file %s\n",
					lineno, pc->name);
			exit(EXIT_FAILURE);
		}

		/* Only validate against policy if it was supplied */
		if (pol->file.name) {

			if (sepol_context_from_string(pol->handle, tmp_context, &tmp_con) < 0) {
				log_error("Out of memory %s\n",
						pc->name);
				exit(EXIT_FAILURE);
			}

			if (sepol_context_check(pol->handle, pol->db, tmp_con) < 0) {
				log_error("Could not validate security context %s on line: %u\n"
						"In file: %s\n", tmp_context, lineno, pc->name);
				exit(EXIT_FAILURE);
			}

			sepol_context_free(tmp_con);
		}

		/* Store to hash table */
		pce = malloc(sizeof(*pce));
		if (!pce) {
			log_error("Out of memory\n");
			exit(EXIT_FAILURE);
		}

		pce->data.context = strdup(tmp_context);
		pce->data.property = strdup(tmp_prop);
		pce->data.lineeno = lineno;

		/* Giving the hash table it's own copy of key */
		item.key = strdup(pce->data.property);
		item.data = pce;

		if (!(item.key && pce->data.context && pce->data.property)) {
			log_error("Out of memory\n");
			exit(EXIT_FAILURE);
		}

		/* Does it currently exist? */
		e = hsearch(item, FIND);

		if (e) {
			/* Yes it exits */
			/* Lets avoid casts later */
			t = (prop_list_entry *)e->data;

			/* If you are not overriding/force, finding an existing entry is an error */
			if (!override) {
				log_error("Duplicate entry detected on line %u collides with line %u\n"
						"in file %s\n", lineno, t->data.lineeno, pc->name);
				exit(EXIT_FAILURE);
			}

			/* Free the inards of property context */
			free(t->data.context);
			free(t->data.property);

			/* Leave the existing list container */
			memcpy(&t->data, &pce->data, sizeof(pce->data));

			/* Free the current container */
			free(pce);
		}
		else {
			/* No it does not exist, this is a new entry */
			hsearch(item, ENTER);

			/* Add it to the linked list */
			prop_list_add(ll, pce);
		}
	} /* Done processing file */
	return;
}
