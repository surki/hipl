/***************************************************************************
                           debug.h  -  description
                             -------------------
    begin                : Mon Oct 2 2003
    copyright            : (C) 2003 by ion
    email                : istoica@cs.berkeley.edu
 ***************************************************************************/

#ifndef CHORD_DEBUG_H
#define CHORD_DEBUG_H

#define CHORD_DEBUG_LEVEL  3

#define CHORD_DEBUG(level, x)  if (level <= CHORD_DEBUG_LEVEL) x;

#endif
