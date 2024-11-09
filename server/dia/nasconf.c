/*
 * nasconf.c - init/configure some things...
 *
 * $Id$
 *
 * Jon Trulson, 9/19/1999
 */

#include "misc.h"
                                /* the NasConfig structure is
                                   instantiated from within
                                   globals.c */
#include "nasconf.h"

/* Initialize the global config items */

void
diaInitGlobalConfig(void)
{
    /* init all the default values */
    NasConfig.DoDebug = FALSE;
    NasConfig.DoVerbose = FALSE;
    NasConfig.DoDeviceRelease = TRUE;
    NasConfig.DoKeepMixer = TRUE;
    NasConfig.DoDaemon = FALSE;
    NasConfig.LocalOnly = FALSE;        /* allow only local connections */
    NasConfig.AllowAny = FALSE; /* allow any host to connect w/o
                                   authentication */

    /* that be it */
    return;
}
