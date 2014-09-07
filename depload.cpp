/*
 * Copyright (c) 2012, Brandon Falk <bfalk@gamozolabs.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 	1. Redistributions of source code must retain the above copyright notice,
 * 	this list of conditions and the following disclaimer.
 *
 * 	2. Redistributions in binary form must reproduce the above copyright
 * 	notice, this list of conditions and the following disclaimer in the
 * 	documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <idp.hpp>
#include <loader.hpp>
#include <diskio.hpp>
#include <nalt.hpp>
#include <name.hpp>
#include <auto.hpp>

struct _imname {
	char *name;
	int   trunc;
};

struct _imports {
	struct _imports *next;

	char filename[0];
};

struct _imports  loadedbase = { 0 };
struct _imports *loadedend  = &loadedbase;

/* isloaded()
 *
 * Summary:
 *
 * This function is used to check if we have already loaded a file. It simply
 * goes through the linked list comparing strings.
 *
 * Parameters:
 *
 * const char *filename - Filename to check
 *
 * Returns:
 *
 * 0 if filename is not loaded
 * 1 if filename is loaded
 */
int
isloaded(const char *filename)
{
	struct _imports *ptr;

	ptr = loadedbase.next;
	while(ptr){
		if(!strcmp(filename, ptr->filename))
			return 1;

		ptr = ptr->next;
	}

	return 0;
}

/* listloaded()
 *
 * Summary:
 *
 * This function lists out the current loaded imports.
 */
void
listloaded(void)
{
	struct _imports *ptr;

	msg(
			"--------------------------\n"
			"Currently loaded files:\n"
			"--------------------------\n");

	ptr = loadedbase.next;
	while(ptr){
		msg(">>>> '%s'\n", ptr->filename);
		ptr = ptr->next;
	}

	return;
}

/* importenum()
 *
 * Summary:
 *
 * This is the enum callback for clearcmts().
 */
int idaapi
importenum(ea_t ea, const char *name, uval_t ord, void *param)
{
	set_cmt(ea, "", true);
	return 1;
}

/* clearcmts()
 *
 * Summary:
 *
 * This function iterates through all import names and wipes their repeatable
 * comments. This is a workaround to what seems to be a bug in IDA.
 */
void
clearcmts(void)
{
	int imports, i;

	imports = get_import_module_qty();

	for(i = 0; i < imports; i++)
		enum_import_names(i, importenum, NULL);

	return;
}

/* load()
 *
 * Summary:
 *
 * This function loads the file specified by filename into the database.
 *
 * Parameters:
 *
 * const char *filename - File to load
 *
 * Returns:
 *
 * -2 if the file is already loaded
 * -1 if the file failed to load
 *  0 if the file loaded successfully
 */
int
load(const char *filename)
{
	char    segn[QMAXPATH], *file;
	int     segs, segsa;
	size_t  fnlen;

	segment_t   *segm;
	linput_t    *linput;
	load_info_t *loadinfo;

	struct _imports *ptr;

	if(isloaded(filename))
		return -2;

	linput = open_linput(filename, false);
	if(!linput)
		return -1;

	loadinfo = build_loaders_list(linput);
	if(!loadinfo){
		close_linput(linput);
		return -1;
	}

	fnlen = strlen(filename) + 1;
	ptr   = (struct _imports*)malloc(sizeof(struct _imports) + fnlen);
	if(!ptr){
		free_loaders_list(loadinfo);
		close_linput(linput);
		return -1;
	}

	if(!load_nonbinary_file(filename, linput, ".",
			NEF_SEGS | NEF_RSCS | NEF_IMPS | NEF_CODE, loadinfo)){
		free(ptr);
		free_loaders_list(loadinfo);
		close_linput(linput);
		return -1;
	}
	segsa = get_segm_qty();
	for(segs = 0; segs < segsa; segs++){
		segm = getnseg(segs);
		if(!segm)
			continue;

		if(get_segm_name(segm, segn, sizeof(segn)) == -1)
			continue;

		if((file = get_segment_cmt(segm, false))){
			qfree(file);
			continue;
		}

		file = strrchr((char*)filename, '\\');
		if(!file)
			continue;

		file++;
		set_segm_name(segm, "%s", file);

		sprintf_s(segn, sizeof(segn), "\ndep: %s\n", filename);
		set_segment_cmt(segm, segn, false);
	}

	free_loaders_list(loadinfo);
	close_linput(linput);

	ptr->next = NULL;
	memcpy(ptr->filename, filename, fnlen);

	loadedend->next = ptr;
	loadedend       = ptr;

	return 0;
}

/* term()
 *
 * Summary:
 *
 * This is the term handler for when our plugin is unloaded. We free all of
 * the linked lists here.
 */
void idaapi
term(void)
{
	struct _imports *ptr, *ptr2;

	ptr = loadedbase.next;
	while(ptr){
		ptr2 = ptr->next;
		free(ptr);
		ptr  = ptr2;
	}

	return;
}

/* init()
 *
 * Summary:
 *
 * This is called when our plugin is loaded. We *should* do some checking here
 * but we don't for now.
 */
int idaapi
init(void)
{
	return PLUGIN_OK;
}

/* enumcb()
 *
 * Summary:
 *
 * This is the enumeration callback for the enumerate_files() function we call.
 * In this function we look for a filename matching the one we're searching
 * for case-insensitively.
 */
int idaapi
enumcb(const char *file, void *ud)
{
	char *sb;

	sb = strrchr((char*)file, '\\');
	if(!sb)
		return 0;

	sb++;
	if(!strnicmp(sb, (char*)ud, strlen((char*)ud)))
		return 1;

	return 0;
}

/* importmap()
 *
 * Summary:
 *
 * This is the enum callback for mapinexports().
 */
int idaapi
importmap(ea_t ea, const char *name, uval_t ord, void *param)
{
	char   comment[MAXSTR];
	size_t len;

	struct _imname *imname;

	/* We only care about imports with names */
	if(!name)
		return 1;

	imname = (struct _imname*)param;

	len = strlen(imname->name);
	if(!strncmp(name, imname->name, len)){
		/* De-truncate */
		*(imname->name + len) = '_';

		sprintf_s(comment, sizeof(comment), "import -> %s", imname->name);
		set_cmt(ea, comment, true);

		/* Re-truncate */
		*(imname->name + len) = 0;
	}

	return 1;
}

/* mapinexports()
 *
 * Summary:
 *
 * This function goes through all functions, searches for a public one. Then
 * checks if there are any imports to that function. If there are, a repeatable
 * comment is set to point to that function from that import.
 */
void
mapinexports(void)
{
	char   fname[MAXSTR], *ptr, *ptr2;
	int    imports, i2;
	size_t funcs, i;

	func_t *func;
	area_t  limits;

	struct _imname imname;

	funcs = get_func_qty();

	for(i = 0; i < funcs; i++){
		if(!(i % 5)){
			replace_wait_box("HIDECANCEL\nMapping imports to exports %6d/%6d",
					i, funcs);
		}

		func = getn_func(i);
		if(!func)
			continue;

		get_func_limits(func, &limits);
		
		if(!is_public_name(limits.startEA))
			continue;

		if(!get_func_name(limits.startEA, fname, sizeof(fname)))
			continue;

		imname.trunc = 0;

		/* If the function name is *_xxxx where the x's are all numbers,
		 * assume it was a rename and chop off the end
		 */
		ptr = strrchr(fname, '_');
		if(ptr){
			ptr2 = ptr + 1;

			while(*ptr2){
				if(*ptr2 < '0' || *ptr2 > '9'){
					/* Mark that it's not just numeric */
					ptr2 = NULL;
					break;
				}
				ptr2++;
			}

			/* Truncate if the findings were numbers only */
			if(ptr2){
				imname.trunc = 1;
				*ptr         = 0;
			}
		}

		/* It cant possibly be the actual function if it isn't renamed
		 * This could save a looooot of time by only working with
		 * truncated entries
		 */
		if(imname.trunc){
			imname.name = fname;
			imports     = get_import_module_qty();
			for(i2 = 0; i2 < imports; i2++)
				enum_import_names(i2, importmap, &imname);
		}
	}

	return;
}

void idaapi
run(int arg)
{
	int     imports, i, method, segs, old;
	char    path[QMAXPATH], buf[QMAXPATH], buf2[QMAXPATH], *ptr, *cmt;
	ssize_t fnlen;

	segment_t *segm;

	struct _imports *iptr;

	/* Add comments to original segments, and load up a previous sessions's
	 * state
	 */
	old  = 0;
	segs = get_segm_qty();
	for(i = 0; i < segs; i++){
		segm = getnseg(i);
		if(!segm)
			continue;

		cmt = get_segment_cmt(segm, false);
		if(!cmt){
			set_segment_cmt(segm, "\ndep: original\n", false);
			continue;
		}

		fnlen = strlen(cmt);
		/* Reload the linked list from an old IDA instance */
		if(fnlen < 6 || memcmp(cmt, "\ndep: ", 6)){
			qfree(cmt);
			continue;
		}

		cmt   += 6;
		fnlen -= 6;
		*(cmt + fnlen - 1) = 0;

		if((fnlen == 9 && !memcmp(cmt, "original", 9)) || isloaded(cmt)){
			qfree(cmt - 6);
			continue;
		}

		iptr = (struct _imports*)malloc(sizeof(struct _imports) + fnlen);
		if(!iptr){
			qfree(cmt - 6);
			warning("Failed to allocate memory for restoring linked list");
			continue;
		}

		iptr->next = NULL;
		memcpy(iptr->filename, cmt, fnlen);

		loadedend->next = iptr;
		loadedend       = iptr;

		/* Note that we loaded up info from an old session */
		old++;

		qfree(cmt - 6);
	}

	if(old){
		msg("Detected %d previous loaded files\n", old);
		listloaded();
	}

	method = askbuttons_c("File", "Dependencies", "Cancel", ASKBTN_CANCEL,
			"Load all current import dependencies or load a single file?\n");

	if(method == ASKBTN_CANCEL)
		return;

	*path = 0;
	if(method == ASKBTN_NO){
		if(!AskUsingForm_c(
				"STARTITEM 0\n"
				"Select Folder\n\n"
				"<Resource folder:F:64:64::>\n", path))
			return;

		imports = get_import_module_qty();
		for(i = 0; i < imports; i++){
			get_import_module_name(i, buf, sizeof(buf) - 4);

			if(!enumerate_files(buf2, sizeof(buf2), path, "*", enumcb, buf)){
				warning("Cannot find resource for import '%s'\nIgnoring.\n", buf);
				continue;
			}

			if(load(buf2) == -1)
				warning("Failed to load file '%s'\n", buf2);
		}
	} else if(method == ASKBTN_YES){
		ptr = askfile_c(0, path, "Select a file to load");
		if(ptr){
			i = load(ptr);
			if(i == -1)
				warning("Failed to load file\n");
			else if(i == -2)
				warning("File is already loaded\n");
		}
	}

	/* This is a kludge to clear all repeatable comments in all imports.
	 * For some reason when NEF_NAME is set for load_nonbinary_file, the
	 * names of the functions are mixed up to the point that functions
	 * are renamed after completely different functions. Without this flag,
	 * everything behaves as we want it to. However, without the flag, imports
	 * are spammed with extremely long repeatable comments with multiple lines.
	 * Here we blindly wipe out all comments to clean this up. I don't think
	 * there are any automatic repeatable comments on import tables that
	 * actually matter, so this kludge isn't a big deal.
	 */
	clearcmts();

	listloaded();

	show_wait_box("HIDECANCEL\nPlease wait for autoanalysis to finish");
	autoWait();
	mapinexports();
	hide_wait_box();
	
	msg("All done\n");
	return;
}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION, /* version */
	0,                     /* flags   */
	init,                  /* init    */
	term,                  /* term    */
	run,                   /* run     */
	NULL,                  /* comment */
	NULL,                  /* help    */
	"depload",             /* name    */
	NULL                   /* hotkey  */
};

