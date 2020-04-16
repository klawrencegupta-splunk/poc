#!/usr/bin/env python
#
# getstacks.py -- print backtraces in a format compatible with flamegraph.pl
# input can be taken either from a live instance or from saved pstacks (including
# tarballs/zipfiles of pstacks) or many other formats

USAGE = """
Usage:
  getstacks.py [-v] [-F] [-J] [-I] [-d] [-u] [-t <thread_id>] [-L pstack|dtrace|sample] [-s <seconds>] [-p <sample_period>] [-m [!]<glob>] [-E <executable>] <pathname... | pid | ->

  -v: Verbose mode.  Specify twice for really verbose.

  -F: Directly output a flamegraph SVG (requires flamegraph.pl)  You can
      also pass flamegraph.pl options to this script as well.

  -J: Instead of stackcollapse-style output, emit a line-delimited stream of JSON
      objects
 
  -I: Include "inactive" stacks, i.e. ones that seem to be intentionally
      blocking on a condition varaible, by polling, etc.  By default only
      threads that appear to be attempting work are output.

  -d: Leave stacks "dirty".  By default the stacks are cleaned up slightly
      to remove uninteresting functions to make things more readable.

  -u: By default, the output is sorted with the most common stacks first.
      If this option is specified, output is returned unsorted.

  -t: Only include stacks for a particular thread (LWP) id.  This option
      can be included multiple times.

  -L: Choose what tool to use to capture stacks of a running process.  Default
      is to guess something reasonable for the local system.

  -s: For live probing, how many seconds should we capture stacks for.
      Default is 20 seconds.

  -p: For live probing, how often should we try to capture stacks.  This value
      can be suffixed by 'hz', 'ms', 'us', or 'ns'.  It also can be prefixed by
      '/' to indicate 'hz' (i.e. "-p /97" to capture 97 times per second).
      By default we will try to pick a reasonable value for the tool being used.

  -m: When reading a tarball, zipfile, or direcory only look at filenames that
      match a particular glob.  Can be specified multiple times, in which case
      the files need to match any one of them.  If starting with a '!' instead
      excludes the file (i.e. -m '!*.tmp')

  -E: Path to the executable being traced.  Required when reading a .prof file
      from google profiler.  This isn't used when reading pstack files.
      For windows .dmp files, this can be the path to the .pdb file that contains
      the symbols.

  -l: Change the output sample counts to be log-scaled.  This is handy if you
      want to see more of the rarer stacks, but it does make the flamegraph
      visually deceptive.

  -R: Remove stacks which start with this function(s) (Comma seperated). This
      can be useful if you want to see the active stacks that aren't waiting
      for a pthread_mutex_lock for example.

  If a pathname is passed as an argument it can be a directory, tarball, or
  zipfile of pstack files, or it can be a pidfile or $SPLUNK_HOME to capture
  the live-running splunkd.  If the pathname is "-" data from a single thread
  will be read from standard input.

  When passed a tarball or zipfile, it will use some heuristics to try to guess
  which files inside are likely to contain pstack data, unless an explicit
  policy is specified with "-m".  Often just:
     $ getstacks.py -F pstacks.tar.gz > pstacks.svg
  is all that is needed to create a flamegraph from customer stacks.

  If the filename looks likely to be a splunk diag, it will just look at
  the crashlogs -- this is handy to quickly determine if a large number
  of crashes share the similar backtraces.

  The script tries its best to autodetect the format of each file it is
  given. Currently it supports reading the input from:
    * Many pstack/procstack variants
    * Dtrace
    * Flamegraph input (such as our own default output or stackcollapse-*.pl)
    * Google Profiler ("pprof --text --stacks" or "pprof -traces") output.
      We can also run that command automatically if given an .prof file as input
    * Splunk crash logs
    * Some support for reading output from debuggers such as gdb, lldb,
      and the windows debugger
    * OS/X commands like "sample" and "stackshot".  Some CSV exports from
      Instruments.app may work as well.
    * Parallel Tools Consortium (typically seen on AIX)
"""

import sys
import os

verbose_level = 0
verbose_owed_newline = False

def verbose_dot_finish():
    global verbose_owed_newline
    if verbose_owed_newline:
        sys.stderr.write('\n')
        verbose_owed_newline = False

def verbose(msg, level = 1):
    if verbose_level >= level:
        verbose_dot_finish()
        sys.stderr.write(msg + '\n')

def verbose_without_newline(msg, level = 1):
    if verbose_level > level:
        global verbose_owed_newline
        sys.stderr.write(msg)
        verbose_owed_newline = True

def verbose_dot():
    if verbose_level == 1:	# we only print dots with "-v", with "-vv" there is too much other stuff going on
        verbose_without_newline('.')

# Remove all template parameters from a string.  It would be handy to keep
# some of these, but the STL often all sorts of std::less/std::alloc nonsense
# so its easier to just drop them all
def untemplatize(funcname):
    if funcname.startswith("operator<"):
        # We want a string like "operator<< <Guid>" to untemplatize just to "operator<<"
        p = funcname.find(' ')
        if p >= 0:
            return funcname[0:p]
    rv = ""
    level = 0
    for c in funcname:
        if c == '>':
            level -= 1
        if level == 0:
            rv += c
        if c == '<':
            level += 1
    return rv

def starts_with_hex_digits(str, count):
    if len(str) < count:
        return False
    for i in range(0, count):
        if str[i] not in "0123456789abcdefABCDEF":
            return False
    if len(str) == count:
        return True
    return str[count] in " \t"

def demangler_trace(msg):
    pass   # sys.stderr.write(msg + "\n")

# Given a string that starts with a string prefixed by its size, returns
# both the encoded string and whatever was remaining.  i.e. if you
# call it with "3foo3bar" it will return "foo","3bar"
def remove_counted_prefix(x):
    num = ""
    while x != "" and x[0] in "0123456789":
        num += x[0]
        x = x[1:]
    if num == "":
        return None, None
    num = int(num)
    if num == 0 or len(x) < num:
        return None, None
    return x[0:num], x[num:]

def remove_gxx_qualifiers_of(x, choices):
    while True:
        if x == "":
            return None
        if x[0] not in choices:
            return x
        x = x[1:]

def remove_gxx_cv_qualifiers(x):
    return remove_gxx_qualifiers_of(x, "rVK")

def remove_gxx_ref_qualifiers(x):
    if x is not None and x != "":
        if x[0] in "RO":
            return x[1:]
    return x

def remove_gxx_type(x):
    demangler_trace("REMOVING TYPE %s" % x)
    x = remove_gxx_cv_qualifiers(x)
    if x is None:
        return None
    if x[0] in "abcdefghijlmnostvwxyz":
        return x[1:]	# built-in basic type
    if x[0] == 'u':
        return x[1:]	# vendor type
    if x[0] == 'F':
        return remove_gxx_function_type(x)
    if x[0] in "0123456789NZ":
        return remove_gxx_name(x)
    if x[0] == 'A':
        x = x[1:]
        if x == "":
            return None
        if x[0] in "0123456789_":
            p = x.find('_')
            if p == -1:
                return None
            return x[p + 1:]
        return remove_gxx_expression(x)
    if x[0] == 'M':	# Pointer to member type
        x = remove_gxx_type(x[1:])
        if x is not None:
            if x == "":
                return None
            x = remove_gxx_type(x)
        return x
    if x[0] == 'T':
        return None # TODO d_template_param
    if x[0] == 'S':
        dont_care, x = remove_gxx_substitution(x)
        return x
    if x[0] in "OPRCGU":	# various type spefifiers
        return remove_gxx_type(x[1:])
    if x[0] == 'D':
        x = x[1:]
        if x == "":
            return None
        if x[0] in "Tt":	# decltype
            return remove_gxx_expression(x[1:])
        if x[0] == 'p':		# Pack type
            return remove_gxx_type(x[1:])
        if x[0] in "afdehsin":
            return x[1:]
        if x[0] == 'F':
            return None		# we don't handle fixed point right now
        if x[0] == 'v':
            return None		# we don't handle vector points right now
        return None
    return None

def remove_gxx_name(x):
    demangler_trace("REMOVING NAME %s" % x)
    if x == "":
        return None
    if x[0] == 'N':
        return remove_gxx_nested_name(x)
    if x[0] == 'Z':
        return remove_gxx_local_name(x)
    if x[0] == 'S':
        dont_care, x = remove_gxx_substitution(x)
        return x
    return remove_gxx_unqualified_name(x)

def remove_gxx_nested_name(x):
    demangler_trace("REMOVING NESTED NAME %s" % x)
    x = x[1:]	# remove 'N' character
    if x == "":
        return None
    x = remove_gxx_cv_qualifiers(x)
    x = remove_gxx_ref_qualifiers(x)
    while True:
        if x is None or x == "":
            return None
        if x[0] == 'E':
            return x[1:]
        if x[0:2] == "DT":
            x = remove_gxx_type(x)
        elif x[0:2] == "Dt" or x[0] in "0123456789abcdefghijklmnopqrstuvwxyzCUL":
            x = remove_gxx_unqualified_name(x)
        elif x[0] == 'S':
            dont_care, x = remove_gxx_substitution(x)
        elif x[0] == 'I':
            x = remove_gxx_template_spec(x)
        elif x[0] == 'T':
            x = None   # TODO d_template_param
        else:
            x = None

def remove_gxx_local_name(x):
    demangler_trace("REMOVING LOCAL NAME %s" % x)
    return None		# TODO

def remove_gxx_function_type(x):
    demangler_trace("REMOVING FUNCTION TYPE %s" % x)
    x = x[1:]		# remove 'F' character
    if x.startswith('Y'):
        x = x[1:]	# indicates C linkage
    x = remove_gxx_bare_function_type(x, True)
    return remove_gxx_ref_qualifiers(x)

def remove_gxx_bare_function_type(x, has_return_type):
    demangler_trace("REMOVING BARE FUNCTION TYPE %s" % x)
    if x.startswith('J'):
        has_return_type = True
        x = x[1:]
    if has_return_type:
        x = remove_gxx_type(x)
        if x is None:
            return None
    return remove_gxx_parmlist(x)

def remove_gxx_parmlist(x):
    demangler_trace("REMOVING PARAM LIST %s" % x)
    while True:
        if x is None or x == "":
            return None
        if x[0] in "E.":
            return x[1:]
        if x[0:2] in [ "RE", "OE" ]:
            return x[2:]
        x = remove_gxx_type(x)

def remove_gxx_unqualified_name(x):
    if x == "":
        return None
    if x[0] in "0123456789":
        dont_care, x = remove_counted_prefix(x)
        return x
    if len(x) >= 2:
        if x[0:2] in GXX_MANGLED_OPERATORS:
            return x[2:]
        if x[0] in "CD":
            return x[2:]
        if x[0:2] == "Ul":
            return None	# TODO d_lambda
        if x[0:2] == "Ut":
            return None
    if x[0] == 'L':
        return None	# TODO get d_source_name and d_discriminator
    if x[0] == 'B':
        return None	# TODO d_abi_tags
    return None

# Given a g++ mangling substitution (which start with a leading 'S') return
# the class that it refers to and the unused part of the string
def remove_gxx_substitution(x):
    x = x[1:]		# remove leading 'S'
    if x == "":
        return None, None
    if x[0] == 't':
        return [ "std" ], x[1:]
    if x[0] == 'a':
        return [ "std", "allocator" ], x[1:]
    if x[0] == 'b':
        return [ "std", "basic_string" ], x[1:]
    if x[0] == 's':
        return [ "std", "string" ], x[1:]
    if x[0] == 'i':
        return [ "std", "istream" ], x[1:]
    if x[0] == 'o':
        return [ "std", "ostream" ], x[1:]
    if x[0] == 'd':
        return [ "std", "iostream" ], x[1:]
    if x[0] in "_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        # These encode referecnces to previous entries in the expansion
        # as base-64 numbers.  We don't compute them, but we do need to
        # skip the right number of characters
        while True:
            if x[0] == '_':
                return [], x[1:]
            x = x[1:]
            if x == "":
                return None, None
    return None, None

# Remove template arguments from the front of a g++ mangled symbol string.
# We do this by continually looking for the 'E' character while respecting
# counted strings
def remove_gxx_template_spec(sym):
   sym = sym[1:]	# remove leading 'I' or 'J'
   while True:
      if sym == "":
          return None
      elif sym[0] == 'E':
          return sym[1:]
      elif sym[0] in "IJ":	# deal with recursive template specs
          sym = remove_gxx_template_spec(sym)
      elif sym[0] == 'S':
          dont_care, sym = remove_gxx_substitution(sym)
      elif sym[0] in "123456789":
          dont_care, sym = remove_counted_prefix(sym)
      elif sym[0] == 'X':
          sym = remove_gxx_expression(sym)
      elif sym[0] == 'L':
          sym = remove_gxx_expression_primary(sym)
      else:
          sym = remove_gxx_type(sym)
      if sym is None:
          return None

def remove_gxx_expression_primary(sym):
    sym = sym[1:]	# remove leading 'L'
    sym = remove_gxx_type(sym)
    if sym is not None:
        p = sym.find('E')
        if p == -1:
            return None
        sym = sym[p + 1:]
    return sym

def remove_gxx_expression(x):
    demangler_trace("REMOVING expression %s" % x)
    return None	# TODO

GXX_MANGLED_OPERATORS = {
    "nw": "_new",
    "na": "_new[]",
    "dl": "_delete",
    "da": "_delete[]",
    "ps": "_unary+",
    "ng": "_unary-",
    "ad": "_unary&",
    "de": "_unary*",
    "co": "~",
    "pl": "+",
    "mi": "-",
    "ml": "*",
    "dv": "/",
    "rm": "%",
    "an": "&",
    "or": "|",
    "eo": "^",
    "aS": "=",
    "pL": "+=",
    "mI": "-=",
    "mL": "*=",
    "dV": "/=",
    "rM": "%=",
    "aN": "&=",
    "oR": "|=",
    "eO": "^=",
    "ls": "<<",
    "rs": ">>",
    "lS": "<<=",
    "rS": ">>=",
    "eq": "==",
    "ne": "!=",
    "lt": "<",
    "gt": ">",
    "le": "<=",
    "ge": ">=",
    "nt": "!",
    "aa": "&&",
    "oo": "||",
    "pp": "++",
    "mm": "--",
    "cm": ",'",
    "pm": "->*",
    "pt": "->",
    "cl": "()",
    "ix": "[]",
    "qu": "?",
    "cv": "_cast",	# Special because it's followed by a type, but we don't care
}

CANT_DEMANGLE = {}
def cant_demangle(symbol):
    if verbose_level > 1:
        global CANT_DEMANGLE
        if symbol not in CANT_DEMANGLE:
            verbose("Couldn't demangle C++ symbol \"%s\"" % symbol, 2)
            CANT_DEMANGLE[symbol] = True

# For function names that start with g++ name mangling (_Z*)
# This doesn't come close to the full decoding but can make something
# readable in many cases
#
# A normal top level function looks like this:
#  _Z10plain_funci
#
# An object inside a class has an "N" qualifier before the name, and E at the end
#  _ZN3ABC11func_in_abcEv
#
# Constructors and destructors have "C" and "D" instead of length-prefixed names:
#
#  _ZN3ABCC1Ev
#  _ZN3ABCD1Ev
#
# For subclasses like ABC::DEF, the extra qualifiers just get added:
#
#  _ZN3ABC3DEF11func_in_defEv
#  _ZN3ABC3DEFC1Ev
#  _ZN3ABC3DEFD1Ev
#
# Namespaces work exactly like subclassses here:
#  _ZN6NSPACE10plain_funcEi
#  _ZN6NSPACE3ABC3DEFD2Ev
#
# "S" introduces a substitution -- for instance St is "std::"
#
#  _ZSt11func_in_stdv
#  _ZNSt10ClassInStd4funcEv
#  _ZNSt10ClassInStdC1Ev
#  _ZNSt10ClassInStdD1Ev
#
# Prior to the name starts (but after N), there can be 'KVr' qualifiers:
#  _ZNKSt10ClassInStd5cfuncEv
#
# For template arguments, they are introduced with an 'I' and end with an 'E':
#  _ZN12HashedStrMapI3StrED1Ev
#  _ZN12HashedStrMapIP20PipelineInputChannelE14_internal_findEPKcmm
#  _ZSt4swapI16SearchableBucketEvRT_S2_
#
# Operators are encoded with special 2-character names in the above table:
#  _ZplO8PathnamePKc
#  _ZNSt6vectorIdSaIdEEaSERKS1_
#
# The most authoratative source for the algorithm is libiberty/cp-demangle.c
# in the gcc source code
#
def z_demangle(symbol):
    x = symbol[2:]	# Remove "_Z"
    if x == "":
        cant_demangle(symbol)
        return symbol
    pieces = []
    if x[0] == "S":
        pieces, x = remove_gxx_substitution(x)
        if x is None or x == "":
            cant_demangle(symbol)
            return symbol
    while x[0] in "PSL":
        x = x[1:]
        if x == "":
            cant_demangle(symbol)
            return symbol
    if x[0] in "123456789":
        p, x = remove_counted_prefix(x)
        if p is None:
            cant_demangle(symbol)
            return symbol
        if x.startswith('I') or x.startswith('J'):
            p += "<>"
        pieces.append(p)
    elif x[0:2] in GXX_MANGLED_OPERATORS:
        pieces.append("operator" + GXX_MANGLED_OPERATORS[x[0:2]])
    elif x[0] == 'N':
        x = x[1:]
        while x != "" and x[0] in "KVr":
            x = x[1:]	# remove things like const/volatile/restrict function qualifiers
        while True:
            if x == "" or x is None:
                cant_demangle(symbol)
                return symbol
            elif x[0:2] in GXX_MANGLED_OPERATORS:
                pieces.append("operator" + GXX_MANGLED_OPERATORS[x[0:2]])
                break
            elif x[0] in "EC":
                break	# Either end of the speficier, or indicating a constructor
            elif x[0] == 'D':
                if len(pieces) == 0:
                    cant_demangle(symbol)
                    return symbol
                pieces.append('~' + pieces.pop())
                break
            elif x[0] == 'S':
                new_pieces, x = remove_gxx_substitution(x)
                if x is None:
                    cant_demangle(symbol)
                    return symbol
                pieces += new_pieces
            elif x[0] in "123456789":
                p, x = remove_counted_prefix(x)
                if p is None:
                    cant_demangle(symbol)
                    return symbol
                pieces.append(p)
            elif x[0] in "IJ":
                x = remove_gxx_template_spec(x)
                if x is None or len(pieces) == 0:
                    cant_demangle(symbol)
                    return symbol
                pieces.append(pieces.pop() + "<>")
            elif x[0] in "LP":
                x = x[1:]	# ignore I guess?
            elif x.startswith("Ut_"):
                x = x[3:]
            else:
                cant_demangle(symbol)
                return symbol
    else:
        cant_demangle(symbol)
        return symbol
    return "::".join(pieces)

import re
MAYBE_AIX_MANGLED_SYMBOL = re.compile("^([^\\d]+)__([1-9].*)[FH]")
AIX_MANGLED_WITH_NAMESPACE = re.compile("^([^\\d]+)__Q[1-9]\\d*_([1-9].*)[FH]")
ANY_LOWERCASE_CHARACTER = re.compile("[a-z]")

# Very crude attempt at demangling AIX symbols.  I'm sure this doesn't handle
# all of the cases
def aix_demangle(symbol):
    m = MAYBE_AIX_MANGLED_SYMBOL.search(symbol)
    if not m:
        m = AIX_MANGLED_WITH_NAMESPACE.search(symbol)
        if not m:
            # Look for bare functions that are mangled like "poll__FPvUll"
            # we want to be a bit careful to avoid false positives on symbole
            # that are all caps etc
            p = symbol.find("__F")
            if p > 0:
                if symbol[p:p + 8] == "FUNCTION":
                    return None
                if not ANY_LOWERCASE_CHARACTER.search(symbol[:p]):
                    return None
                return symbol[:p] 
            return None
    pieces = []
    if symbol.startswith("__dt__"):
        funcname = "~"
    else:
        funcname = m.group(1)
    remain = symbol[m.start(2):]
    while True:
        elem, remain = remove_counted_prefix(remain)
        if elem is None:
            cant_demangle(symbol)
            return None
        pieces.append(elem)
        if remain.startswith('F') or remain.startswith("CF") or remain.startswith('X') or remain.startswith('H'):
            break
    if funcname == "~":
        if len(pieces) == 0:
            cant_demangle(symbol)
            return None
        pieces[-1] = "~" + pieces[-1]
    else:
        pieces.append(funcname)
    return "::".join(pieces)

# In some dumps, template expanded functions include their return value
# (i.e. "bool foo<>(int)")  We want to detect any space-delimited values
# and only consider the last one.  However, there are a couple caveats:
#   * We don't want to worry about spaces inside template expansions
#     at this point
#   * we don't want to break up "operator new"
#   * a return value can have template expansions itself, so don't
#     consider spaces inside of <>  For safety, we look at other bracket
#     types as well
def find_space_in_function_name(func):
    result = -1
    angle_level = 0	# <>
    paren_level = 0	# ()
    square_level = 0	# []
    brace_level = 0	# {}
    i = 0
    n = len(func)
    while i < n:
        if func[i] == '<':
            angle_level += 1
        elif func[i] == '>':
            if angle_level > 0:
                angle_level -= 1
        elif func[i] == '(':
            paren_level += 1
        elif func[i] == ')':
            if paren_level > 0:
                paren_level -= 1
        elif func[i] == '[':
            square_level += 1
        elif func[i] == ']':
            if square_level > 0:
                square_level -= 1
        elif func[i] == '{':
            brace_level += 1
        elif func[i] == '}':
            if brace_level > 0:
                brace_level -= 1
        elif (angle_level + paren_level + square_level + brace_level) == 0:
            f9 = func[i:i + 9]
            if f9 == "operator[" or f9 == "operator(":
                i += 9		# skip over operator() / operator[]
            elif f9 == "operator<" or f9 == "operator>" or f9 == "operator ":
                i += 8		# same, but don't skip next byte (which could be '=' or space)
            elif func[i] == ' ':
                result = i + 1
        i += 1
    return result

# System symbols on OS/X that have '$' characters in them are used for a
# variety of link-time rebinding.  We want to just display the interesting segment
def clean_darwin_symbol(func):
    highest_score = -1
    best = None
    pieces = func.split('$')
    if func.startswith("$ld$hide$") and len(pieces) == 5:
        return pieces[4]
    for piece in pieces:
        if piece == "VARIANT" and best is not None:
            break	# cases like _OSAtomicCompareAndSwapLongBarrier$VARIANT$up
        if piece == "":
            continue
        score = len(piece)
        if piece == "fenv_access_off" or not ANY_LOWERCASE_CHARACTER.search(piece):
            score = 0	# common specifiers are in capse "fstat$INODE64", but the math libs use "_ctan$fenv_access_off"
        if score > highest_score:
            best = piece
            highest_score = score
    if best is None:
        return func
    return best

MATCH_GCC_CONSTPROP = re.compile("^(.+)\\.constprop\\.\\d+$")

# Constant-propagation can cause function names like "foo.constprop.123" to appear:
def clean_gcc_constprop(func):
    m = MATCH_GCC_CONSTPROP.search(func)
    if m:
        func = m.group(1)
    return func

def trim_unmangled_function_name(func):
    if func.startswith("(anonymous namespace)::"):
        func = func[23:]
    # We'll assume that the function name is already demangled
    # Collapse templated function names; otherwise STL can cause enormous names
    if func.find('<') >= 0 and func.find('>') >= 0:
        func = untemplatize(func)
    # Remove any prefix of "::"
    if len(func) > 2 and func[0:2] == "::":
        func = func[2:]
    # If the string ends with a "X::~X" signature, get rid of the "X::" part
    p = func.rfind('::~')
    if p >= 0:
        class_name = func[p + 3:]
        if func.endswith(class_name + "::~" + class_name):
            func = func[:len(func) - 3 - (2 * len(class_name))] + '~' + class_name
    # For some reason, sometimes pstack template functions include a return type
    # like "bool foo<...>"  At this point if there's a space character, decide we
    # want the last element.  However, we don't want so strip out "operator foo"
    # or mess unduly with spaces inside the template
    p = find_space_in_function_name(func)
    if p >= 0:
        func = func[p:]
    return clean_gcc_constprop(func)

def demangle_or_trim_function_name(func):
    if func.startswith("_Z"):
        # Name looks like g++ mangling; try to extract a reasonable representation
        return z_demangle(func)
    if func.find("__") >= 0 and func.find(':') == -1:
        # Maybe AIX mangled?
        af = aix_demangle(func)
        if af is not None:
             return af
    return trim_unmangled_function_name(func)

MATCH_CLANG_INTERNAL_NAMESPACE = re.compile("\\bstd::__\\d+::")

# Take something that looks like a function name and make it printable
def clean_function_name(func):
    p = func.find('@')
    if p >= 0:
        func = func[0:p]		# strip endings like "_IO_file_xsputn@@GLIBC_2.2.5"
    func = func.rstrip(' ')
    if func.find('$') >= 0:
        func = clean_darwin_symbol(func)
    func = demangle_or_trim_function_name(func)

    # Clang uses a namespace of "std::__1::" for its internal functions.  Trim out
    # that ugliness
    while True:
        m = MATCH_CLANG_INTERNAL_NAMESPACE.search(func)
        if not m:
            break
        func = func[0:m.start(0)] + "std::" + func[m.end(0):]

    # AIX uses internal "std::_LFS_ON::" namespace
    if func.startswith("std::_LFS_ON::"):
        func = "std::" + func[14:]

    # The final output format uses ';' as its delimiter, so make sure that
    # the function name can't contain that or space
    for avoid_char in [ ';', ' ', '\t' ]:
        func = func.replace(avoid_char, '_')
    if func == "" or func.startswith('?'):
        return None
    return clean_gcc_constprop(func)

# We want to strip a function name starting at its introducing '('.  We
# make an exception for "operator()" where the parens are part of the
# function's name
def find_open_paren_starting_function(str):
    p = str.find('(')
    if p >= 8 and str[p - 8:p + 2] == "operator()":
        p += 2
    return p

# Reads a function name in a lines that can look like:
#   #0  0x0000003c11e0b5bc in pthread_cond_wait@@GLIBC_2.3.2 () from /lib64/libpthread.so.0
#   #1  0x0000000000feca39 in PthreadCondition::wait(ConditionMutex&) ()
#   #2  0x0000000000fe905f in TcpChannelThread::main() ()
#   #3  0x0000000000fecbae in Thread::callMain(void*) ()
#   #4  0x0000003c11e079d1 in start_thread () from /lib64/libpthread.so.0
#
# or:
#
# 000007fe`fd371430 : 331f7ce2`00000002 00000000`32ea5d60 00000000`00000048 0000001a`00000001 : ntdll!ZwWaitForMultipleObjects+0xa
# 00000001`41d6f9a0 : 00000000`00495980 00000000`00486d90 00000000`002efde0 ba808f2a`d1d57600 : splunkd!wmain+0x643 [c:\wrangler-2.0\build-src\manual-build\src\main\loader.cpp @ 3274]
#
# or:
#
# fffffd7ffeb7c6ca pollsys (0, 0, fffffd7ff83fff70, 0)
# fffffd7ffeb1ee02 poll () + 52
# 00000000009c74ee _ZN15FSUpdaterThread4mainEv () + 1e
#
# or:
#
# libc.so.1`_so_setsockopt+0xa
# splunkd`_ZNK18PollableDescriptor10setNoDelayEb+0x2f
# splunkd`_ZNK11TcpOutbound10setNoDelayEb+0x2c
#
# or:
#
# 0xb7719424: _fini
#
# or:
#
# kernel32!GetVolumePathNameW+0x538
#
# or:
# #0  0x00007f892b0ef360 pthread_cond_wait@@GLIBC_2.3.2 - /lib/x86_64-linux-gnu/libpthread-2.23.so
# #1  0x0000563d8f890169 PthreadConditionImpl::wait(ConditionMutex&) - /home/ichaer/releases/splunk-unstripped-7.1.0-2e75b3406c5b/bin/splunkd
# #2  0x0000563d8ecef40b SavedSearchHistory::main() - /home/ichaer/releases/splunk-unstripped-7.1.0-2e75b3406c5b/bin/splunkd
# #3  0x0000563d8f89032f Thread::callMain(void*) - /home/ichaer/releases/splunk-unstripped-7.1.0-2e75b3406c5b/bin/splunkd
# #4  0x00007f892b0e96ba start_thread - /lib/x86_64-linux-gnu/libpthread-2.23.so
# #5  0x00007f892ae1f41d __clone - /lib/x86_64-linux-gnu/libc-2.23.so
#
# or (for the splunk watchdog):
# [0x00007F2CF6A4AE1B]  "? (libpthread.so.0 + 0x9E1B)"
# [0x00007F2CF6A4ACE8]  "pthread_mutex_lock + 104 (libpthread.so.0 + 0x9CE8)"
# [0x00000000017197CD]  "_ZN16PthreadMutexImpl4lockEv + 93 (splunkd + 0x13197CD)"
#
def find_function(line):
    line = line.lstrip(' ')
    if line.count(" : ") >= 2:
        # This looks like windows debugging output; first focus on last component
        line = line.split(" : ")[-1]
        p = line.find(" [")
        if p >= 0 and line.endswith(']'):
            line = line[0:p]
        p = line.find("+0x")
        if p >= 0:
            line = line[0:p]
    else:
        if line.startswith('#'):
            p = line.find(' ')
            if p >= 0:
                line = line[p + 1:]
            line = line.lstrip(' ')
        if line.startswith('['):
            p = max(0, line.find(']')) # if missing ], remove at least [
            line = line[p+1:].lstrip(' "')
        if starts_with_hex_digits(line, 16):
            line = line[17:]
        elif starts_with_hex_digits(line, 8):
            line = line[9:]
        elif line.startswith("0x"):
            if starts_with_hex_digits(line[2:18], 16):
                line = line[18:]
                if line.startswith(": "):
                    line = line[2:]
            elif starts_with_hex_digits(line[2:10], 8):
                line = line[10:]
                if line.startswith(": "):
                    line = line[2:]
        if line.count('`') == 1:	# remove dtrace/lldb binary name
            p = line.find('`')
            line = line[p + 1:]
        if line.startswith("non-virtual thunk to "):	# lldb backtraces insert these
            line = line[21:]
        p = line.find(" from ")
        if p >= 0:
            line = line[0:p]
        line = line.rstrip(' ')
        p = line.find(" in ")
        if p >= 0:
            line = line[p + 4:]
        p = find_open_paren_starting_function(line)
        if p >= 0:
            line = line[0:p]
        p = line.find(' - /')
        if p >= 0:
            line = line[0:p]
        p = line.find("+0x")
        if p >= 0:
            line = line[0:p]
        else:
            p = line.find(" + ")
            if p >= 0:
                line = line[0:p]
    p = line.find('!')
    if p >= 0 and (p < 8 or line[p - 8:p] != "operator"):
        line = line[p + 1:]
    return clean_function_name(line)

FIND_FUNCTION_NAME_IN_GOOGLE_PROFILER_OUTPUT = re.compile(":\\d+:(.*)$")

# Google stack lines look like:
#   (0000003bc2271c57) ??:0:_IO_file_xsputn@@GLIBC_2.2.5
#   (0000000000bc5dea) /home/mitch/git/splunk/src/pipeline/indexer/test/DumpRawdata.cpp:94:print_event
# It's possible that the filename contains a colon, and the function certainly
# can.  Therefore we scan looking for the line number in between to colons, which
# hopefully won't match anything in the filename.
def find_google_profiler_function(line):
    line = line.strip()
    if not line.startswith('('):
        return None
    p = 1
    while p < len(line) and line[p] in "0123456789abcdefABCDEF":
        p += 1
    if p not in [9, 17]:	# look for 32-bit or 64-bit values
        return None
    if p >= len(line) or line[p] != ')':
        return None
    m = FIND_FUNCTION_NAME_IN_GOOGLE_PROFILER_OUTPUT.search(line[p + 1:])
    if not m:
        verbose("Couldn't find symbol in google profiler output: \"%s\"" % line[p + 1:])
        return None
    if m.group(1).startswith("0x"):
        return None
    return clean_function_name(m.group(1))

# Splunk crashlog lines look like:
#  [0x000000000101F08F] _ZN6Thread8callMainEPv + 79 (splunkd)
#  [0x0000003BC2A079D1] ? (/lib64/libpthread.so.0)
# or on OS/X:
#    Frame  0                      :  [0x000000010677ACF5] _ZN15backtracer_test8crash_meEv + 69 (BacktracerTest + 0x3CF5)
#    Frame  1 @[0x00007FFEE94885E0]:  [0x000000010677AC99] _ZN15backtracer_test3cccEv + 9 (BacktracerTest + 0x3C99)
def find_splunk_crashlog_function(line):
    line = line.strip()
    if line.startswith("Frame"):
        colon_pos = line.find(':')
        if colon_pos < 0:
            return None
        line = line[colon_pos + 1:].lstrip()
    if not line.startswith("[0x"):
        return None
    p = 3
    while p < len(line) and line[p] in "0123456789ABCDEF":
        p += 1
    if p not in [11, 19]:	# look for 32-bit or 64-bit values
        return None
    if p >= len(line) - 1 or line[p:p + 2] != "] ":
        return None
    remain = line[p + 2:]
    p = remain.find(" + ")
    q = remain.find(" (")
    if q >= 0 and (q < p or p < 0):
        p = q
    if p >= 0:
        remain = remain[:p]
    if remain == "?":
        remain = "??"	# more similar to pstack's output
    return clean_function_name(remain)

FIND_OSX_SAMPLE_ADD_DECIMAL_AT_END = re.compile(" \\+ \\d+(,\\d+(,\\.\\.\\.)?)?$")
FIND_OSX_SAMPLE_IN_OBJECT_AT_END = re.compile("  \\(in .*\\)$")

# OS/X's "sample" tool emits functions that look like:
#   thread_start  (in libsystem_pthread.dylib) + 13
def find_osx_sample_function(line):
    line = line.strip()
    m = FIND_OSX_SAMPLE_ADD_DECIMAL_AT_END.search(line)
    if m:
        line = line[:m.start()]
    m = FIND_OSX_SAMPLE_IN_OBJECT_AT_END.search(line)
    if m:
        line = line[:m.start()]
    p = find_open_paren_starting_function(line)
    if p >= 0:
        line = line[:p]
    return clean_function_name(line)

MEMCHECK_STRIP_FILE_AND_LINE = re.compile("^(.*) \\(.*:\\d+\\)$")
MEMCHECK_STRIP_ONLY_FILE = re.compile("^(.*) \\(in /.*\)$")

def find_memcheck_function(line):
    if line.startswith("(below main)"):
        return None
    # Remove the actual lines inside valgrind's malloc replacement since
    # they're not the interesting part of the callstack
    for item in [ "vg_replace_malloc.c:", "new_op.cc:", "new_opv.cc:" ]:
        if line.find(item) >= 0:
            return None
    m = MEMCHECK_STRIP_FILE_AND_LINE.search(line)
    if m:
        line = m.group(1)
    else:
        m = MEMCHECK_STRIP_ONLY_FILE.search(line)
        if m:
            line = m.group(1)
    p = find_open_paren_starting_function(line)
    if p >= 0:
        line = line[:p]
    for ignore_starting_with in [ "__libc_csu_init", "_GLOBAL__", "__static_initialization_and_destruction" ]:
        if line.startswith(ignore_starting_with):
            return None
    return clean_function_name(line)

STACK_COLLAPSE_FORMAT = re.compile("^([^\\t]+[^ \\t]) ([1-9]\\d*)$")
STACK_COLLAPSE_EMPTY_STACK = re.compile("^ ([1-9]\\d*)$")

def object_from_our_own_output(line):
    m = STACK_COLLAPSE_FORMAT.search(line)
    if not m:
        m = STACK_COLLAPSE_EMPTY_STACK.search(line)
        if not m:
            return None
        return { "stack": [], "count": int(m.group(1)) }
    return { "stack": m.group(1).split(';'), "count": int(m.group(2)) }

# Some formats like Instruments' CSV export format give stacks as trees
# where each line is indented to show its level.  This class handles
# tracking the running stack and yielding objects as leaf nodes are found
class TopDownIndentedStackParser:
    def __init__(self):
        self.stack = []
        self.counts = []

    def add(self, level, symbol, samples):
        # If the previously seen trace is at this level (or higher) we
        # need to emit some items
        for obj in self.finish(level):
            yield obj
        while len(self.stack) < level + 1:
            self.stack.append(symbol)
            self.counts.append(samples)

    def finish(self, level = 0):
        while len(self.stack) > level:
            c = self.counts.pop()
            if c > 0:
                yield { "stack": self.stack, "count": c }
                self.counts = [ v - c for v in self.counts ]
            self.stack.pop()

FIND_PTCCORE_THREAD_NUMBER = re.compile("Thread (\\d+)")

class ParallelToolsConsortiumLightweightCorefileFormat:
    def __init__(self):
        self.obj = None
        self.tid = None
        self.in_stack = False

    def parse(self, line):
        if line.startswith("+++STACK"):
            self.in_stack = True
            self.obj = {}
            self.obj["stack"] = []
        elif line.startswith("---STACK"):
            for o in self.finish():
                yield o
            self.in_stack = False
        elif line.startswith("+++ID "):
            m = FIND_PTCCORE_THREAD_NUMBER.search(line)
            if m:
                self.tid = m.group(1)
            else:
                verbose("Couldn't find thread number in PTC corefile line: \"%s\"" % line)
        elif line.startswith("---ID "):
            self.tid = None
        elif line == "" or line.startswith('#') or line.startswith('***') or line.startswith("+++") or line.startswith("---"):
            pass
        elif self.in_stack:
            p = line.find(" : ")
            if p > 0:
                f = clean_function_name(line[0:p])
                if f is None:
                    verbose("Couldn't find function name in PTC corefile line: \"%s\"" % line)
                else:
                    self.obj["stack"].insert(0, f)
            else:
                verbose("Couldn't parse line in PTC stack: \"%s\"" % line)
        else:
            verbose("Couldn't parse line inside PTC corefile: \"%s\"" % line)

    def finish(self):
        if self.obj is not None:
            if self.tid is not None:
                 self.obj["tid"] = self.tid
            yield self.obj
            self.obj = None

def wrapped_utf16le_reader(fileobj):
    import codecs
    data_info = codecs.lookup("utf-8")
    file_info = codecs.lookup("utf-16le")
    return codecs.StreamRecoder(fileobj, data_info.encode, data_info.decode, file_info.streamreader, file_info.streamwriter, "strict")

# A simple abstraction around a file objects that returns line-by-line results, and also has
# a method of pushing back lines that we ended up wanting to re-parse
class FileLinesWithPushBack:
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.pushed_back = []
        self.owed_str = b""
        # If first bytes are "FF FE" then we want to auto-convert from UTF-16le.  This
        # is produced by tools like cdb.exe on windows.  If it starts with a UTF-8 BOM
        # (EF BB BF) just strip it.  Otherwise, if the first byte is NUL but the second
        # byte isn't assume UTF-16
        byte1 = fileobj.read(1)
        if len(byte1) > 0:
            if ord(byte1) == 0xFF:
                byte2 = fileobj.read(1)
                if len(byte2) > 0:
                    if ord(byte2) == 0xFE:
                        verbose("Detected UTF-16LE BOM", 2)
                        self.fileobj = wrapped_utf16le_reader(self.fileobj)
                    else:
                        self.owed_str = byte1 + byte2
                else:
                    self.owed_str = byte1
            elif ord(byte1) == 0xEF:
                byte2 = fileobj.read(1)
                if len(byte2) > 0:
                    if ord(byte2) == 0xBB:
                        byte3 = fileobj.read(1)
                        if len(byte3) > 0:
                            if ord(byte2) == 0xBF:
                                verbose("Detected UTF-8 BOM", 2)
                            else:
                                self.owed_str = byte1 + byte2 + byte3
                        else:
                            self.owed_str = byte1 + byte2
                    else:
                        self.owed_str = byte1 + byte2
                else:
                    self.owed_str = byte1
            elif ord(byte1) == 0x0:
                byte2 = fileobj.read(1)
                if len(byte2) > 0:
                    if ord(byte2) != 0x0:
                        verbose("Detected UTF-16LE input", 2)
                        self.fileobj = wrapped_utf16le_reader(self.fileobj)
                        self.owed_str = byte2
                    else:
                        self.owed_str = byte1 + byte2
                else:
                    self.owed_str = byte1
            else:
                self.owed_str = byte1
        if sys.version_info >= (3, 0):
            self.owed_str = self.owed_str.decode("utf-8")
        pos = self.owed_str.find('\n')
        if pos >= 0:
            self.pushed_back = self.owed_str.split('\n')
            if pos == len(self.owed_str) - 1:
                self.owed_str = ""
            else:
                self.owed_str = self.pushed_back.pop()
            self.pushed_back.reverse()
    def getline(self):
        if len(self.pushed_back) > 0:
            return self.pushed_back.pop()
        if self.fileobj is None:
            return None
        line = self.fileobj.readline()
        if not line:
            self.fileobj.close()
            self.fileobj = None
            return None
        if sys.version_info >= (3, 0):
            line = line.decode("utf-8")
        rv = self.owed_str + line
        self.owed_str = ""
        return rv.rstrip()
    def push(self, line):
        self.pushed_back.append(line)
    # We can also act like an iterator (needed to interact with csv.DictReader)
    # In this mode we act like a normal file object and return strings including
    # their newlines
    def __iter__(self):
        return self
    def next(self):
        line = self.getline()
        if line is None:
            raise StopIteration()
        return line + "\n"
    
MATCH_OSX_STACKSHOT_FIRST_LINE = re.compile("^Build Version: [\\dA-F]+$")
MATCH_OSX_STACKSHOT_THREAD = re.compile("^    Thread ID: 0x([\\da-f])+$")
MATCH_OSX_STACKSHOT_NON_STACK_ITEM = re.compile("^    [A-Z][A-Za-z _]*: .")

# OS/X's /usr/libexec/stackshot program emits stacks in its own peculiar
# format.  To run it, do:
#   $ sudo sh -c ':> /Library/Logs/stackshot-syms.log'
#   $ sudo /usr/libexec/stackshot -u -i -p <pid> [-n <count>] -f /tmp/foo
# and it will leave a symbolicated backtrace of the process in
# /Library/Logs/stackshot-syms.log.  Don't bother trying to redirect its
# output using the -f option -- that only changes where the non-symbolicated
# version gets written.  It also doesn't accept /dev/null
#
def read_osx_stackshot_format(reader):
    obj = None
    tid = None
    while True:
        line = reader.getline()
        if line is None:
            break
        m = MATCH_OSX_STACKSHOT_THREAD.search(line)
        if m:
            if obj is not None:
                yield obj
                obj = None
            tid = m.group(1)
        elif line == "    User stack:":
            if obj is not None:
                yield obj
            obj = {}
            obj["stack"] = []
            if tid is not None:
                obj["tid"] = tid
                tid = None
        elif MATCH_OSX_STACKSHOT_NON_STACK_ITEM.search(line):
            if obj is not None:
                yield obj
                obj = None
        elif obj is not None:
            if line.startswith(' ' * (4 + len(obj["stack"]))):
                func = find_function(line.strip())
                if func is not None:
                    obj["stack"].insert(0, func)
                elif not line.strip().startswith("0x"):
                    verbose("Couldn't find function in stackshot line: \"%s\"" % line)
            else:
                yield obj
                obj = None

MATCH_LINUX_PERF_SCRIPT_THREAD = re.compile("^[^ \\t].* (\\d+) +\\[")
MATCH_LINUX_PERF2_SCRIPT_THREAD = re.compile("^\\S+\\s+(\\d+)\\s+\\d+\.\\d+:\\s+(\\d+)\\s+cycles")
# Also a stricter version to detect the first one if it didn't print a header
MATCH_LINUX_PERF_SCRIPT_THREAD_STRICTER = re.compile("^[^ \\t].* \\d+ +\\[\\d+\\][ \\t]+\\d+\\.\\d\\d\\d\\d\\d\\d: |^\\S+\\s+\\d+\\s+\\d+\.\\d+:\\s+\\d+\\s+cycles")
MATCH_LINUX_PERF_SCRIPT_FUNCTION = re.compile("^[ \\t]+[\\da-f]+( +[^ ].*)$")
MATCH_LINUX_PERF_SCRIPT_KERNEL_LOCATION = re.compile("^(.* )\\(\\[(.*)]\\)$")
MATCH_LINUX_PERF_SCRIPT_REMOVE_FILENAME = re.compile("^(.*) \\([^\\)]+\\)$")

# Helper for read_linux_perf_script_data which drops empty stack and massages EventLoop ones
def yield_linux_perf_script_stack(obj, thread_started_in_kernel):
   if obj is None:
      return
   if len(obj["stack"]) == 0:
      return
   if obj["stack"][-1] == "EventLoop::run" and thread_started_in_kernel:
      # This is probably an inactive stack, but we just didn't get visibility
      # on the syscall.  Just add one so looks_active() will do the right thing
      obj["stack"].append("syscall")
   yield obj

# Read output of "perf script" command
def read_linux_perf_script_data(reader):
    obj = None
    thread_started_in_kernel = False
    while True:
        line = reader.getline()
        if line is None:
            break
        if line == "":
            for obj in yield_linux_perf_script_stack(obj, thread_started_in_kernel):
                yield obj
            obj = None
            continue
        count = 1
        m = MATCH_LINUX_PERF2_SCRIPT_THREAD.search(line)
        if m:
            count = m.group(2)
        else:
            m = MATCH_LINUX_PERF_SCRIPT_THREAD.search(line)
        if m:
            for obj in yield_linux_perf_script_stack(obj, thread_started_in_kernel):
                yield obj
            obj = {}
            obj["stack"] = []
            obj["tid"] = m.group(1)
            obj["count"] = count
            thread_started_in_kernel = False
            continue
        if obj is not None:
            m = MATCH_LINUX_PERF_SCRIPT_FUNCTION.search(line)
            if m:
                sym = m.group(1)
                m = MATCH_LINUX_PERF_SCRIPT_KERNEL_LOCATION.search(sym)
                if m:
                    if m.group(2) == "vdso" or m.group(2).startswith("kernel."):
                        if len(obj["stack"]) == 0:
                            thread_started_in_kernel = True
                        continue
                    sym = m.group(1)
                sym = sym.strip()
                if sym.startswith('('):		# no symbol found just possibly a filename
                    continue
                m = MATCH_LINUX_PERF_SCRIPT_REMOVE_FILENAME.search(sym)
                if m:
                    sym = m.group(1)
                sym = find_function(sym)
                if sym is not None:
                    obj["stack"].insert(0, sym)
                continue
        verbose("Couldn't parse line in \"perf script\" output: \"%s\"" % line)
    for obj in yield_linux_perf_script_stack(obj, thread_started_in_kernel):
        yield obj

MATCH_LINUX_PSTACK_THREAD = re.compile("LWP (\\d+)")
MATCH_WINDOWS_DEBUGGER_THREAD = re.compile("\\d+ +Id: [0-9a-f]+\\.([0-9a-f]+) Suspend:")
MATCH_SOLARIS_PSTACK_THREAD = re.compile("thread# (\\d+) ")
MATCH_SOLARIS_PSTACK_FIRST_LINE_CORE = re.compile("^core '.*' of \\d+: ")
MATCH_ONLY_DIGITS_WITH_WHITESPACE = re.compile("^[ \t]*(\\d+)$")
MATCH_FIRST_LINE_OF_GOOGLE_PROFILER_OUTPUT = re.compile("^Total: \\d+ samples$")
MATCH_GOOGLE_PROFILER_EPILOGUE_LINE = re.compile("^ *\\d+ +\\d+\\.\\d% +\\d+\\.\\d% +\\d+ +\\d+\\.\\d% ")
MATCH_LEADING_NONZERO_NUMBER = re.compile("^([1-9]\\d*)( .*)$")
# AIX procstack's first line gives the PID and the command being run, separated by " : "
MATCH_AIX_PROCSTACK_FIRST_LINE = re.compile("^[1-9]\\d* ?: ")
MATCH_AIX_PROCSTACK_THREAD_ID = re.compile(" tid# ([1-9]\\d*) ")
MATCH_LLDB_THREAD_HEADER = re.compile("^[ \\*] thread #\\d+: tid = 0x([\\da-f]+),")
MATCH_LLDB_FRAME = re.compile("^  [ \\*] frame #\\d+: 0x([\\d+a-f]+) (.*)$")
FIND_FIRST_NON_SPACE = re.compile("[^ ]")
MATCH_OSX_SAMPLE_FIRST_LINE = re.compile("^Analysis of sampling .* \\(pid [1-9]\\d*\\) every [1-9]\\d* milliseconds$")
MATCH_OSX_SAMPLE_THREAD = re.compile("^    \\d+ Thread_(\\d+)")
MATCH_OSX_SAMPLE_FUNCTION = re.compile("^    [ \\+\\|:!]+([1-9]\\d*) (.*)  \\[0x[\\da-f]+(,0x[\\da-f]+(,\\.\\.\\.)?)?\\]$")
MATCH_OSX_SAMPLE_HEXADDR = re.compile("^    [ \\+\\|:!]+([1-9]\\d*) 0x[\\da-f]+$")
# HP/UX's format is very similar to AIX but the spacing is (luckily) different
MATCH_HPUX_PSTACK_FIRST_LINE = re.compile("^\\d+:   /")
MATCH_HPUX_PSTACK_THREAD = re.compile("^--------------------------------  lwpid : (\\d+)   -------------------------------$")
MATCH_HPUX_PSTACK_FUNCTION = re.compile("^ *\\d+: [\\da-f]+ : (.*)$")
MATCH_SPLUNK_CRASHLOG_FIRST_LINE = re.compile("^\\[build [\\da-f]+\\]")
MATCH_SPLUNK_CRASHLOG_BACKTRACE = re.compile("^ +Backtrace.*:$") 
MATCH_SPLUNK_CRASHLOG_FUNCTION = re.compile("^ +\\[0x[\\dA-F]{8}([\\dA-F]{8})?\\] (.*$)")
MATCH_SPLUNK_CRASHLOG_APPLE_FUNCTION = re.compile("^ +Frame +\\d+ +(@\\[0x[\\dA-F]{8}([\\dA-F]{8})?\\])?: +\\[0x[\\dA-F]{8}([\\dA-F]{8})?\\] (.*$)")
MATCH_MAYBE_CLASSIC_LINUX_PSTACK_HEADER = re.compile("^[1-9]\\d*: ")
MATCH_CLASSIC_LINUX_PSTACK_LINE = re.compile("^0x[\\da-f]{8}([\\da-f]{8})?: (.*) \\+ 0x[\\da-f]+ \\([\\da-f]+, [\\da-f]+, [\\da-f]+, [\\da-f]+, [\\da-f]+, [\\da-f]+\\) \\+ [\\da-f]+$")
MATCH_GDB_MI_THREAD_HEADER = re.compile("^~\"\\\\nThread \\d+ \\(Thread 0x[\\da-f]+ \\(LWP (\\d+)\\)\\):\\\\n\"$")
MATCH_GDB_THREAD_HEADER = re.compile("^Thread \\d+ \\(Thread 0x[\\da-f]+ \\(LWP (\\d+)\\)\\):$")
MATCH_VALGRIND_MEMCHECK_FIRST_LINE = re.compile("^==\\d+== Memcheck")
MATCH_VALGRIND_MEMCHECK_LEAK_RECORD_START = re.compile("^==\\d+== ([0-9,]+) bytes .* in loss record ")
MATCH_VALGRIND_MEMCHECK_LEAK_RECORD_FUNC = re.compile("^==\\d+== +[ab][ty] 0x[0-9A-F]+: (.+)$")
MATCH_LINUX_EUSTACK_HEADING = re.compile("^(?:TID \\d+:|PID \\d+ - process)$")
MATCH_LINUX_EUSTACK_HEADING_MEMORYMAP = re.compile("^PID \\d+ - process module memory map$")
MATCH_LINUX_EUSTACK_THREAD = re.compile("^TID (\\d+):$")
MATCH_LINUX_EUSTACK_SOURCEANNOTATION = re.compile("^\\s+(?:\\.{1,2}|/).*:\\d+$")
MATCH_LINUX_EUSTACK_BUILDIDANNOTATION = re.compile("^\\s+\\[[0-9a-fA-F]+\\]")

DETECTED_LINUX_PSTACK = 1
DETECTED_SOLARIS_PSTACK = 2
DETECTED_SINGLETHREAD_PSTACK = 3	# some pstack format, no thread boundaries
DETECTED_OURSELVES = 4			# apparently fed our own input for futher filtering
DETECTED_WINDOWS_DEBUGGER = 5
DETECTED_DTRACE = 6
DETECTED_GOOGLE_PROFILER_STACKS = 7	# output from "pprof --text --stacks"
DETECTED_AIX_PROCSTACK = 8
DETECTED_LLDB = 9			# output of lldb's "bt all", etc
DETECTED_INSTRUMENTS_CSV_OUTPUT = 10	# Instruments stacks, exported as CSV
DETECTED_OSX_SAMPLE = 11		# OS/X's "sample" command
DETECTED_HPUX_PSTACK = 12
DETECTED_PARALLEL_TOOLS_CONSORTIUM = 13
DETECTED_SPLUNK_CRASHLOG = 14
DETECTED_CLASSIC_LINUX_PSTACK = 15	# the old non-gdb based pstack from 32-bit linux
DETECTED_GDB_MI = 16			# output of gdb in "--interpreter=mi" mode
DETECTED_GDB = 17			# output of gdb in normal mode
DETECTED_OSX_STACKSHOT = 18		# OS/X's "/usr/libexec/stackshot -u" command
DETECTED_LINUX_PERF_SCRIPT_COMMAND = 19
DETECTED_VALGRIND_MEMCHECK = 20		# Output of valgrind, we'll produce a summary of bytes leaked
DETECTED_GO_PPROF_TRACES = 21		# Output of "pprof -traces" output (go version, not the old perl one)
DETECTED_LINUX_EUSTACK = 22		# Output of elfutils' eu-stack

DESCRIBE_DETECTED_FORMAT = {
    DETECTED_LINUX_PSTACK: "linux-style pstacks",
    DETECTED_SOLARIS_PSTACK: "solaris-style pstacks",
    DETECTED_SINGLETHREAD_PSTACK: "pstack without thread information",
    DETECTED_OURSELVES: "stackcollapse-style input",
    DETECTED_WINDOWS_DEBUGGER: "windows debugger output",
    DETECTED_DTRACE: "dtrace stacks",
    DETECTED_GOOGLE_PROFILER_STACKS: "google profiler output",
    DETECTED_AIX_PROCSTACK: "AIX procstacks",
    DETECTED_LLDB: "LLDB stacks",
    DETECTED_INSTRUMENTS_CSV_OUTPUT: "CSV export from OS/X Instruments",
    DETECTED_OSX_SAMPLE: "OS/X sample command's output",
    DETECTED_HPUX_PSTACK: "HP/UX-style pstacks",
    DETECTED_PARALLEL_TOOLS_CONSORTIUM: "parallel tools consortium lightweight corefile format",
    DETECTED_SPLUNK_CRASHLOG: "splunk crash log",
    DETECTED_CLASSIC_LINUX_PSTACK: "old-style linux pstack",
    DETECTED_GDB_MI: "gdb --interpreter=mi output",
    DETECTED_GDB: "gdb output",
    DETECTED_OSX_STACKSHOT: "OS/X stackshot command's output",
    DETECTED_LINUX_PERF_SCRIPT_COMMAND: "linux \"perf script\" command",
    DETECTED_VALGRIND_MEMCHECK: "valgrind memcheck leak-detection",
    DETECTED_GO_PPROF_TRACES: "pprof -traces output (go version)",
    DETECTED_LINUX_EUSTACK: "linux elfutils's \"eu-stack\" command",
}

def looks_like_gdb_starting_up(line):
    for start in [ "GNU gdb", "Attaching to process ", "Reading symbols from ", "Loaded symbols for ", "[Thread debugging using", "[New Thread ", "[New LWP ", "Currently logging to \"" ]:
        if line.startswith(start):
            return True
    if MATCH_GDB_THREAD_HEADER.search(line):
        return True
    return False

MATCH_YEAR = re.compile("\\b20\\d{2}\\b") # 20YY
# HH:MM:SS -- in hour, any digit may follow 0 and 1, but only 0-3 may follow 2, and in some situations 24:00:00 is the preferred way of expressing midnight
MATCH_TIME = re.compile("\\b(?:(?:[0-1]\\d|2[0-3])(?::[0-5]\\d){2}|24:00:00)\\b")
def ignore_before_detection(line):
    return MATCH_YEAR.search(line) and MATCH_TIME.search(line)

last_detected = None
def now_detected(d):
    global last_detected
    if d != last_detected:
        verbose("Detected " + DESCRIBE_DETECTED_FORMAT[d])
        last_detected = d

MATCH_LINUX_PERF_REPORT_HEADER_LINE = re.compile("^# \\.[\\. ]*$")

# Reads data in "perf script" format
def read_linux_perf_script(reader):
    detected = None
    while True:
        line = reader.getline()
        if line is None:
            break
        if line.startswith('#'):
            if detected is None:
                m = MATCH_LINUX_PERF_REPORT_HEADER_LINE.search(line)
                if m:
                    # I spent a long time trying to writer a parser for 'perf report's
                    # output, but from the samples I found, it does not always show the
                    # correct branch weights!  Eventually I gave up; "perf script" is
                    # what you're supposed to use for automated parsing anyway
                    verbose("Ignoring result of 'perf report', use 'perf script' instead")
                    while line is not None:
                        line = reader.getline()
                    return
            continue
        if line == "":
            continue
        if detected is None and (MATCH_LINUX_PERF_SCRIPT_THREAD.search(line) or MATCH_LINUX_PERF2_SCRIPT_THREAD.search(line)):
            detected = DETECTED_LINUX_PERF_SCRIPT_COMMAND
            now_detected(detected)
            reader.push(line)
            for o in read_linux_perf_script_data(reader):
                yield o
            return
        verbose("Couldn't parse line while reading linux 'perf script' command \"%s\"" % line, 2)

MATCH_GO_PPROF_TRACES_DIVIDER = re.compile("^--[-\\+]*--$")
MATCH_GO_PPROF_FIRST_IN_SECTION = re.compile("^[ \t]*(\\d+)([a-z]+)[ \t]+([^ \\t]+)$")

GO_PPROF_TIME_UNITS_TO_NANOSECONDS = {
    "ns": 1,
    "nanosecond": 1,
    "us": 1000,
    "microsecond": 1000,
    "ms": 1000 * 1000,
    "millisecond": 1000 * 1000,
    "sec": 1000 * 1000 * 1000,
    "second": 1000 * 1000 * 1000,
    "s": 1000 * 1000 * 1000,
    "min": 1000 * 1000 * 1000 * 60,
    "minute": 1000 * 1000 * 1000 * 60,
    "hr": 1000 * 1000 * 1000 * 60 * 60,
    "hour": 1000 * 1000 * 1000 * 60 * 60,
    "day": 1000 * 1000 * 1000 * 60 * 60 * 24,
    "week": 1000 * 1000 * 1000 * 60 * 60 * 24 * 7,
    "wk": 1000 * 1000 * 1000 * 60 * 60 * 24 * 7,
    "year": 1000 * 1000 * 1000 * 60 * 60 * 24 * 365,
    "yr": 1000 * 1000 * 1000 * 60 * 60 * 24 * 365,
}

# The (newer 'go' version of) pprof outputs the count as a duration in
# time.  It also auto-scales it a human-readable unit, so we have to unscale it
# to get back to nanoseconds.  See internal/measurement/measurement.go
def go_pperf_from_units(n, units):
    return n * GO_PPROF_TIME_UNITS_TO_NANOSECONDS[units]

# Reads data in the format the the go version of "pprof -traces" outputs
# NOTE: this is distinct from the older perl-based version of pprof
def read_go_pperf_traces(reader):
    state = 0
    obj = None
    while True:
        line = reader.getline()
        if line is None:
            break
        if MATCH_GO_PPROF_TRACES_DIVIDER.search(line):
            if obj is not None:
                yield obj
                obj = None
            state = 1
        elif state == 1:    # First line of a section
            m = MATCH_GO_PPROF_FIRST_IN_SECTION.search(line)
            if m:
                obj = {}
                obj["stack"] = []
                if m.group(3) != "<unknown>":
                    obj["stack"].insert(0, trim_unmangled_function_name(m.group(3)))
                obj["count"] = go_pperf_from_units(int(m.group(1)), m.group(2))
                state = 2
        elif state == 2:
            func = line.strip()
            if func != "<unknown>":
                obj["stack"].insert(0, trim_unmangled_function_name(line.strip()))
    if obj is not None:
        yield obj

# Reads the output of a pstack command, and yields a stream of objects
# describing each stack it found
def read_pstack_file_object(fileobj):
    reader = FileLinesWithPushBack(fileobj)
    obj = None
    detected = None
    expecting_gdb_backtrace = False

    while True:
        line = reader.getline()
        if line is None:
            break

        # If we're at the top of the file, see if we need to skip some header lines
        if detected is None:
            if line.startswith("Opened log file ") or line.find("Windows Debugger") >= 0:
                # This is a file captured from the windows debugger; skip until we see a thread header
                detected = DETECTED_WINDOWS_DEBUGGER
                now_detected(detected)
                while True:
                    line = reader.getline()
                    if line is None:
                        verbose("Found no end to preamble of windows debugger output")
                        return
                    if MATCH_WINDOWS_DEBUGGER_THREAD.search(line):
                        break
            elif MATCH_FIRST_LINE_OF_GOOGLE_PROFILER_OUTPUT.search(line):
                detected = DETECTED_GOOGLE_PROFILER_STACKS
                now_detected(detected)
                while True:
                    line = reader.getline()
                    if line is None:
                        verbose("Found no end to preamble of google profiler output")
                        return
                    if len(line) > 0 and line[0] in "123456789":
                        break
            elif MATCH_AIX_PROCSTACK_FIRST_LINE.search(line):
                detected = DETECTED_AIX_PROCSTACK
                now_detected(detected)
                continue
            elif line.find("PARALLEL TOOLS CONSORTIUM LIGHTWEIGHT COREFILE FORMAT") >= 0:
                detected = DETECTED_PARALLEL_TOOLS_CONSORTIUM
                now_detected(detected)
                parser = ParallelToolsConsortiumLightweightCorefileFormat()
                while True:
                    line = reader.getline()
                    if line is None:
                        break
                    for o in parser.parse(line):
                        yield o
                for o in parser.finish():
                    yield o
                return
            elif line == "# ========":
                for obj in read_linux_perf_script(reader):
                    yield obj
                return
            elif line.startswith("(lldb) ") or MATCH_LLDB_THREAD_HEADER.search(line):
                detected = DETECTED_LLDB
                now_detected(detected)
            elif line.count(',') >= 2 and line.find("Symbol Name") >= 0 and line.find("Samples") >= 0:
                now_detected(DETECTED_INSTRUMENTS_CSV_OUTPUT)
                parser = TopDownIndentedStackParser()
                import csv, itertools
                reader = csv.DictReader(itertools.chain([line], reader))
                for row in reader:
                    symbol = row["Symbol Name"]
                    m = FIND_FIRST_NON_SPACE.search(symbol)
                    if not m:
                        verbose("Symbol name had no space characters")
                        continue
                    level = m.start()
                    symbol = symbol[level:]
                    samples = int(row["Samples"].split(' ')[0])
                    for obj in parser.add(level, symbol, samples):
                        yield obj
                for obj in parser.finish():
                    yield obj
                return
            elif MATCH_VALGRIND_MEMCHECK_FIRST_LINE.search(line):
                detected = DETECTED_VALGRIND_MEMCHECK
                now_detected(detected)
            elif line.find("FUNCTION:NAME") >= 0:
                # This is a preamble we can get with dtrace-captured
                # data.  Discard until first blank line
                detected = DETECTED_DTRACE
                now_detected(detected)
                while True:
                    line = reader.getline()
                    if line is None:
                        verbose("Found no end to preamble of dtrace output")
                        return
                    if line == "":
                        break
                continue
            elif MATCH_SPLUNK_CRASHLOG_FIRST_LINE.search(line):
                while True:
                    line = reader.getline()
                    if line is None:
                        return	# truncated crashlog
                    if MATCH_SPLUNK_CRASHLOG_BACKTRACE.search(line):
                        break
                line = reader.getline()
                if line is None:
                    return	# truncated crashlog
                if MATCH_SPLUNK_CRASHLOG_FUNCTION.search(line) or MATCH_SPLUNK_CRASHLOG_APPLE_FUNCTION.search(line):
                    detected = DETECTED_SPLUNK_CRASHLOG
                    now_detected(detected)
                elif line.find("PARALLEL TOOLS CONSORTIUM LIGHTWEIGHT COREFILE FORMAT") >= 0:
                    # on AIX, we dump PCG dumps straight into the crashlog file!
                    # however for the sake of '-v' we'll still call it a crashlog
                    detected = DETECTED_SPLUNK_CRASHLOG
                    now_detected(detected)
                    parser = ParallelToolsConsortiumLightweightCorefileFormat()
                    while True:
                        line = reader.getline()
                        if line is None:
                            break
                        if line.count(" / ") == 4:
                            # This is probably the uname line after the backtrace, so skip the rest of it
                            while True:
                                line = reader.getline()
                                if line is None:
                                    break
                            break
                        for o in parser.parse(line):
                            yield o
                    for o in parser.finish():
                        yield o
                    return
                else:
                    verbose("Can't parse first line of splunk backtrace: \"%s\"" % line)
                    return
            elif MATCH_SPLUNK_CRASHLOG_FUNCTION.search(line) or MATCH_SPLUNK_CRASHLOG_APPLE_FUNCTION.search(line):
                detected = DETECTED_SPLUNK_CRASHLOG
                now_detected(detected)
            elif line == " Backtrace:" or line == "Backtrace:":
                # Sometimes people quote a crashlog starting with " Backtrace:"
                # However don't assume it's in true splunk crashlog format
                # since on AIX it can be in PCG format
                continue
            elif MATCH_OSX_SAMPLE_FIRST_LINE.search(line):
                now_detected(DETECTED_OSX_SAMPLE)
                while True:
                    line = reader.getline()
                    if line is None:
                        verbose("Never found call graph in sample output!")
                        return
                    if line.startswith("Call graph:"):
                        break
                parser = TopDownIndentedStackParser()
                current_thread = None
                while True:
                    line = reader.getline()
                    if line is None:
                        break
                    if line == "":
                        break
                    m = MATCH_OSX_SAMPLE_THREAD.search(line)
                    if m:
                        for obj in parser.finish():
                            if current_thread is not None:
                                obj["tid"] = current_thread
                            yield obj
                        current_thread = m.group(1)
                    else:
                        m = MATCH_OSX_SAMPLE_FUNCTION.search(line)
                        if m:
                            f = find_osx_sample_function(m.group(2))
                            if f is not None:
                                for obj in parser.add((m.start(1) / 2) - 3, f, int(m.group(1))):
                                    if current_thread is not None:
                                        obj["tid"] = current_thread
                                    yield obj
                        else:
                            m = MATCH_OSX_SAMPLE_HEXADDR.search(line)
                            if m:
                                # We didn't get a function, just a hex
                                # address.  Just put it in as "??" like
                                # pstack would
                                for obj in parser.add((m.start(1) / 2) - 3, "??", int(m.group(1))):
                                    if current_thread is not None:
                                        obj["tid"] = current_thread
                                    yield obj
                            else:
                                verbose("Couldn't parse line from OS/X sample output: \"%s\"" % line)
                for obj in parser.finish():
                    if current_thread is not None:
                        obj["tid"] = current_thread
                    yield obj
                while line is not None:
                    line = reader.getline()
                return
            elif MATCH_HPUX_PSTACK_FIRST_LINE.search(line):
                detected = DETECTED_HPUX_PSTACK
                now_detected(detected)
                continue
            elif line.startswith("=thread-group-added") or line.startswith("~\""):
                detected = DETECTED_GDB_MI
                now_detected(detected)
                continue
            elif looks_like_gdb_starting_up(line):
                detected = DETECTED_GDB
                now_detected(detected)
                while not MATCH_GDB_THREAD_HEADER.search(line):
                    line = reader.getline()
            elif line.startswith("Python Exception ") and line.find("No module named gdb") >= 0:
                # gdb can print some python errors if it doesn't find its modules
                # This can happen both in normal and MI mode, so just eat until newline
                while True:
                    line = reader.getline()
                    if line is None or line == "":
                        break
                if line is None:
                    verbose("Couldn't find an end to the Python exception at the top of gdb output")
                    break
                continue
            elif MATCH_MAYBE_CLASSIC_LINUX_PSTACK_HEADER.search(line):
                # The linux one is fairly indistinct, so check the next line as well
                next_line = reader.getline()
                if next_line == "(No symbols found)" or next_line.startswith("(No symbols found in ") or MATCH_CLASSIC_LINUX_PSTACK_LINE.search(next_line):
                    detected = DETECTED_CLASSIC_LINUX_PSTACK
                    now_detected(detected)
                    line = next_line
                else:
                    reader.push(next_line)	# un-read that second line
            elif MATCH_OSX_STACKSHOT_FIRST_LINE.search(line):
                detected = DETECTED_OSX_STACKSHOT
                now_detected(detected)
                for obj in read_osx_stackshot_format(reader):
                    yield obj
                return
            elif MATCH_SOLARIS_PSTACK_FIRST_LINE_CORE.search(line):
                detected = DETECTED_SOLARIS_PSTACK
                now_detected(detected)
                continue
            elif MATCH_LINUX_PERF_SCRIPT_THREAD_STRICTER.search(line):
                reader.push(line)
                for obj in read_linux_perf_script(reader):
                    yield obj
                return
            elif line.startswith("File: "):
                detected = DETECTED_GO_PPROF_TRACES
                now_detected(detected)
                for obj in read_go_pperf_traces(reader):
                    yield obj
                return
            elif MATCH_LINUX_EUSTACK_HEADING.match(line) or MATCH_LINUX_EUSTACK_HEADING_MEMORYMAP.match(line):
                detected = DETECTED_LINUX_EUSTACK
                now_detected(detected)
                if MATCH_LINUX_EUSTACK_HEADING_MEMORYMAP.match(line):
                    while True:
                        line = reader.getline()
                        if line is None or MATCH_LINUX_EUSTACK_HEADING.match(line):
                            break
            elif ignore_before_detection(line):
                verbose("Skipping line="+line, level=2)
                continue
        # End of the "detected is None" case

        if detected == DETECTED_OURSELVES:
            obj = object_from_our_own_output(line)
            if obj is None:
                verbose("Couldn't parse stackcollapse format: \"%s\"" % line)
                raise RuntimeError("Misdetected input as our own format") 
            yield obj
        elif detected == DETECTED_SPLUNK_CRASHLOG:
            if line.startswith("  [") or line.startswith("    Frame "):
                func = find_splunk_crashlog_function(line)
                if func is not None:
                    if obj is None:
                        obj = {}
                        obj["stack"] = []
                    obj["stack"].insert(0, func)
            elif not line.startswith("Args:  "):
                # we must be past the backtrace part now; ignore anything else in the crashlog
                while True:
                    line = reader.getline()
                    if line is None:
                        break
                break
        elif detected == DETECTED_GDB_MI:
            m = MATCH_GDB_MI_THREAD_HEADER.search(line)
            if m:
                if obj is not None:
                    yield obj
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
            elif obj is not None:
                if line.startswith('^'):
                    yield obj
                    obj = None
                elif line.startswith("~\"#") and line.endswith("\\n\""):
                    f = find_function(line[2:-3])
                    if f:
                        obj["stack"].insert(0, f)
        elif detected == DETECTED_GDB:
            m = MATCH_GDB_THREAD_HEADER.search(line)
            if m:
                if obj is not None:
                    yield obj
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
            elif obj is not None:		# backtrace in progress
                if line == "" or line.startswith("(gdb) "):
                    yield obj
                    obj = None
                    expecting_gdb_backtrace = line.startswith("(gdb) backtrace") or line.startswith("(gdb) bt")
                elif line.startswith('#'):
                    f = find_function(line)
                    if f:
                        obj["stack"].insert(0, f)
                    expecting_gdb_backtrace = False	# now that we're mid-object
            elif expecting_gdb_backtrace and line.startswith("#0  "):	# backtrace of just one thread?
                obj = {}
                obj["stack"] = []
                f = find_function(line)
                if f:
                    obj["stack"].insert(0, f)
            elif line.startswith("(gdb) backtrace") or line.startswith("(gdb) bt"):
                expecting_gdb_backtrace = True
        elif line == "":
            if detected == DETECTED_DTRACE:
                if obj is not None and len(obj["stack"]) > 0:
                    yield obj
                obj = {}
                obj["stack"] = []
            elif detected == DETECTED_GOOGLE_PROFILER_STACKS:
                if obj is not None and len(obj["stack"]) > 0:
                    yield obj
                obj = None
        elif detected == DETECTED_GOOGLE_PROFILER_STACKS:
            if obj is None:
                if MATCH_GOOGLE_PROFILER_EPILOGUE_LINE.search(line):
                    # At the end of the function there is a dump of per-function
                    # stats which we're not interested in.  Just consume the data
                    # to keep anything piping to us happy
                    while True:
                        line = reader.getline()
                        if line is None:
                            return
                m = MATCH_LEADING_NONZERO_NUMBER.search(line)
                if not m:
                    verbose("Couldn't parse google profiler stack start: \"%s\"" % line)
                    raise RuntimeError("Failed to parse google profiler output") 
                obj = {}
                obj["stack"] = []
                obj["count"] = int(m.group(1))
                line = m.group(2)
            f = find_google_profiler_function(line)
            if f:
                obj["stack"].insert(0, f)
        elif detected == DETECTED_VALGRIND_MEMCHECK:
            m = MATCH_VALGRIND_MEMCHECK_LEAK_RECORD_START.search(line)
            if m:
                if obj is not None and len(obj["stack"]) > 0:
                    yield obj
                obj = {}
                obj["stack"] = []
                obj["count"] = int(m.group(1).replace(",", ""))
            elif obj is not None:
                m = MATCH_VALGRIND_MEMCHECK_LEAK_RECORD_FUNC.search(line)
                if m:
                    f = find_memcheck_function(m.group(1))
                    if f is not None:
                        obj["stack"].insert(0, f)
                else:
                    yield obj
                    obj = None
        elif detected == DETECTED_WINDOWS_DEBUGGER and MATCH_WINDOWS_DEBUGGER_THREAD.search(line):
            m = MATCH_WINDOWS_DEBUGGER_THREAD.search(line)
            if obj is not None:
                yield obj
            obj = {}
            obj["stack"] = []
            obj["tid"] = m.group(1)
        elif (detected is None or detected == DETECTED_LINUX_PSTACK) and line.startswith("Thread "):
            detected = DETECTED_LINUX_PSTACK
            now_detected(detected)
            if obj is not None:
                yield obj
            obj = {}
            obj["stack"] = []
            m = MATCH_LINUX_PSTACK_THREAD.search(line)
            if m:
                obj["tid"] = m.group(1)
        elif detected == DETECTED_LINUX_EUSTACK:
            if MATCH_LINUX_EUSTACK_SOURCEANNOTATION.match(line) or MATCH_LINUX_EUSTACK_BUILDIDANNOTATION.search(line):
                continue # skip source annotation line
            m = MATCH_LINUX_EUSTACK_THREAD.search(line)
            if m:
                if obj is not None:
                    yield obj
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
            else:
                if obj is None:
                    verbose("Skipping eu-stack line: " + line, level=2)
                else:
                    f = find_function(line)
                    if f:
                        obj["stack"].insert(0, f)
        elif (detected is None or detected == DETECTED_SOLARIS_PSTACK) and line.startswith("----------------- "):
            detected = DETECTED_SOLARIS_PSTACK
            now_detected(detected)
            if obj is not None:
                yield obj
            obj = {}
            obj["stack"] = []
            m = MATCH_SOLARIS_PSTACK_THREAD.search(line)
            if m:
                obj["tid"] = m.group(1)
        elif detected == DETECTED_WINDOWS_DEBUGGER and (line.startswith("RetAddr ") or line.startswith("Child-SP ") or line.startswith("*** ") or line.startswith(" # ") or line.startswith("Closing open log file ") or line == "quit:" or line.startswith("WARNING: ")):
            pass			# Random extra stuff in windows dumps
        elif detected == DETECTED_DTRACE and obj is not None and MATCH_ONLY_DIGITS_WITH_WHITESPACE.search(line):
            m = MATCH_ONLY_DIGITS_WITH_WHITESPACE.search(line)
            obj["count"] = int(m.group(1))
        elif line == "(No symbols found)" or line.startswith("(No symbols found in"):
            pass
        elif detected == DETECTED_AIX_PROCSTACK:
            if line.startswith("---------- tid# "):
                if obj is not None:
                    yield obj
                m = MATCH_AIX_PROCSTACK_THREAD_ID.search(line)
                if not m:
                    verbose("Couldn't parse AIX stack start: \"%s\"" % line)
                    raise RuntimeError("Failed to parse AIX thread number")
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
                continue
            if obj is None:
                obj = {}
                obj["stack"] = []
            f = find_function(line.split(' ', 1)[-1])
            if f:
                obj["stack"].insert(0, f)
        elif detected == DETECTED_HPUX_PSTACK:
            m = MATCH_HPUX_PSTACK_THREAD.search(line)
            if m:
                if obj is not None:
                    yield obj
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
                continue
            m = MATCH_HPUX_PSTACK_FUNCTION.search(line)
            if m:
                f = find_function(m.group(1))
                if f:
                    obj["stack"].insert(0, f)
            else:
                verbose("Couldn't parse HP/UX pstack line: \"%s\"" % line)
        elif detected == DETECTED_LLDB:
            m = MATCH_LLDB_THREAD_HEADER.search(line)
            if m:
                if obj is not None:
                    yield obj
                    obj = None
                # When gdb stop is prints the current thread and frame in the same format
                # so read ahead a couple lines and see if they match that pattern
                line2 = reader.getline()
                if line2 is None:
                    break
                if not MATCH_LLDB_FRAME.search(line2):
                    reader.push(line2)
                    continue
                line3 = reader.getline()
                if line3 is not None:
                    if not line3.startswith(' '):	# probably not a real backtrace, just skip it
                        verbose("Skipping lldb frame printing that ended with \"%s\"" % line3, 2)
                        continue
                    # OK we'll trust that line2/line3 are part of a real backtrace now
                    reader.push(line3)
                reader.push(line2)
                obj = {}
                obj["stack"] = []
                obj["tid"] = m.group(1)
            elif obj is not None:
                f = None
                m = MATCH_LLDB_FRAME.search(line)
                if m:
                    addr = m.group(1)
                    if len(addr) in [8, 16] and starts_with_hex_digits(addr, len(addr)):
                        f = find_function(m.group(2))
                if f is not None:
                    obj["stack"].insert(0, f)
                elif line.find("??") == -1:
                    verbose("Couldn't find function in line: \"%s\"" % line, 2)
        else:
            if obj is None:		# if only a single thread, pstack may not print header
                if detected is None:
                    obj = object_from_our_own_output(line)
                    if obj is not None:
                        detected = DETECTED_OURSELVES
                        now_detected(detected)
                        yield obj
                        obj = None
                        continue
                obj = {}
                obj["stack"] = []
            f = find_function(line)
            if f:
                if detected is None:
                    if line.count(" : ") >= 2:
                        detected = DETECTED_WINDOWS_DEBUGGER
                    elif line.find('`') >= 0:
                        detected = DETECTED_DTRACE
                    else:
                        detected = DETECTED_SINGLETHREAD_PSTACK
                    now_detected(detected)
                obj["stack"].insert(0, f)
            elif line.find("??") == -1:	# normal pstacks emit "??" when they don't find a name
                verbose("Couldn't find function in line: \"%s\"" % line, 2)
    if obj is not None and len(obj["stack"]) > 0:
        yield obj

# Yields a stream of objects describing each stack found in a file
def read_pstack_file(filename):
    try:
        fh = open(filename, "rb")
    except:
        sys.stderr.write("Cannot open \"" + filename + "\"\n")
        return
    for obj in read_pstack_file_object(fh):
        yield obj
    fh.close()

# The pprof tool always writes some stuff to stderr, but we only print
# it out if it returns non-zero
captured_stderr_from_child = b""
def stderr_capturing_thread(fh):
    from threading import Thread
    def stderr_main(fh):
        global captured_stderr_from_child
        captured_stderr_from_child = b""
        while True:
            d = fh.read(4096)
            if not d:
                break
            captured_stderr_from_child += d
    t = Thread(target = stderr_main, args=[fh])
    t.daemon = True
    t.start()
    return t

# Run pstack once and yield the objects we find
def read_google_profiler_file(prof_file, executable_path, pprof_tool):
    # There are two different verions of the "pprof" tool out in the wild -- the
    # modern one written in "go", and an older perl one.  Unfortunately they
    # have to be called in a different way, so we try to detect if we the
    # tool is written in perl:
    pprof_in_perl = False
    try:
        ptf = open(pprof_tool)
        firstline = ""
        while True:
            ch = ptf.read(1)
            if not ch:
                firstline = ""
                break
            if ch == '\n':
                break
            if ch != '\t' and (ord(ch) < 32 or ord(ch) > 126):
                firstline = ""
                break
            if len(firstline) > 500:
                firstline = ""
                break
            firstline += ch
        ptf.close()
        pprof_in_perl = (firstline.find("perl") >= 0)
    except:
        pass
    if pprof_in_perl:
        pprof_command_line = [ find_perl5(), pprof_tool, "--stacks", "--text", executable_path, prof_file ]
    else:
        pprof_command_line = [ pprof_tool, "-traces", executable_path, prof_file ]
    verbose("Running: " + " ".join(pprof_command_line), 2)
    import subprocess
    pprof_process = subprocess.Popen(pprof_command_line, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stderr_thread = stderr_capturing_thread(pprof_process.stderr)
    for obj in read_pstack_file_object(pprof_process.stdout):
        yield obj
    pprof_process.wait()
    stderr_thread.join()
    if pprof_process.returncode != 0:
        verbose("pprof exited with status code %d" % pprof_process.returncode)
        if sys.version_info >= (3, 0):
            captured_stderr_from_child = captured_stderr_from_child.decode()
        sys.stderr.write(captured_stderr_from_child)
        global exit_code
        if exit_code == 0:
             exit_code = pprof_process.returncode

# Run a .dmp file through cdb to extract its stack
def read_windows_dump(dmp_file, executable_path):
    import subprocess
    cdb_command = [ "cdb.EXE" ]
    if executable_path is not None:
        cdb_command += [ "-y", executable_path ]
    cdb_command += [ "-z", dmp_file, "-c", "~*k;q" ]
    cdb_process = subprocess.Popen(cdb_command, stdout=subprocess.PIPE)
    for obj in read_pstack_file_object(cdb_process.stdout):
        yield obj
    cdb_process.wait()

# Detect if a file on disk looks like a linux "perf" data file
def looks_like_linux_perf(filename):
    try:
        with open(filename) as fh:
            magic = fh.read(8)
            return magic=="PERFFILE" or magic=="PERFILE2"
    except:
        return False

def read_linux_perf_file(perf_filename):
    verbose("Treating \"%s\" as a linux perf dump" % perf_filename)
    import subprocess
    perf_process = subprocess.Popen(["/usr/bin/perf", "script", "-i", perf_filename], stdout=subprocess.PIPE)
    for obj in read_pstack_file_object(perf_process.stdout):
        yield obj
    perf_process.wait()

# why not an object with __enter__ and __exit__ which removes the temp file after
# usage? that sort of garbage collection doesn't play nice with yield.
def copy_fileobj_into_tmp(fileobj):
    import tempfile
    bufsz = 1024*1024
    name = None
    with tempfile.NamedTemporaryFile(bufsize=bufsz, suffix='.getstacks', delete=False) as f:
        name = f.name
        while True:
            buf = fileobj.read(bufsz)
            if not buf:
                break
            f.write(buf)
    return name

def read_from_filename(path, executable_path, pprof_tool, file_object=None):
    """If `file_object` is None, read a non-tar/zip file on disk (i.e. something
       that has a simple filename we can either read directly or pass to an
       external program). Otherwise, assume `path` is not on disk -- for
       file types requiring files on disk, create a temporary file with the
       contents of `file_object`, process and then clean up.
    """
    tmpFname = None
    try:
        if path.endswith(".prof"):
            if file_object is not None:
                tmpFname = path = copy_fileobj_into_tmp(file_object)
            g = read_google_profiler_file(path, executable_path, pprof_tool)
        elif path.endswith(".dmp") and sys.platform.startswith("win"):
            if file_object is not None:
                tmpFname = path = copy_fileobj_into_tmp(file_object)
            g = read_windows_dump(path, executable_path)
        elif looks_like_linux_perf(path):
            if file_object is not None:
                tmpFname = path = copy_fileobj_into_tmp(file_object)
            g = read_linux_perf_file(path)
        else:
            if file_object is not None:
                g = read_pstack_file_object(file_object)
            else:
                g = read_pstack_file(path)
        for obj in g:
            yield obj
    finally:
        if tmpFname is not None:
            os.unlink(tmpFname)

# Match things that look like crashlogs splunk generates.  Note taht this
# isn't anchored at the beginning since on windows the pathname gets
# inserted at the front
MATCH_SPLUNK_CRASHLOG_NAME = re.compile("crash-\\d\\d\\d\\d-[01]\\d-[0123]\\d-[012]\\d[-:][012345]\\d[-:][0123456]\\d\\.log$")

def filename_looks_like_crashlog(filename):
    if MATCH_SPLUNK_CRASHLOG_NAME.search(filename.lower()):
        return True
    verbose("Ignoring non-crashlog file: \"%s\"" % filename, 2)
    return False

def dot_log_filename_looks_interesting(squashed_filename):
    if MATCH_SPLUNK_CRASHLOG_NAME.search(squashed_filename):
        return True
    # We may get pstacks from customers that look like "pstack1.log"
    # etc.  Guess it's a pstack if "stack" appears somewhere
    return squashed_filename.find("stack") >= 0

# A list of file extensions that we'll by default ignore if we're reading
# a directory, tarball, or zipfile.  This can be overridden with the "-m"
# option.
BLACKLISTED_EXTENSIONS = {
    "bak": True,
    "bat": True,
    "cfg": True,
    "cmd": True,
    "com": True,
    "conf": True,
    "css": True,
    "csv": True,	# It's possible for CSV's to be perf data (from
                        # Instruments, etc) but is more commonly other things
                        # in a diag, so you have to opt-in with "-m"
    "db": True,
    "default": True,
    "dll": True,
    "egg": True,
    "eot": True,
    "example": True,
    "examples": True,
    "exe": True,
    "gif": True,
    "htm": True,
    "html": True,
    "ico": True,
    "ini": True,
    "jar": True,
    "jpeg": True,
    "jpg": True,
    "js": True,
    "json": True,
    "kmz": True,
    "lic": True,
    "license": True,
    "md": True,
    "meta": True,
    "mmdb": True,
    "mo": True,
    "otf": True,
    "path": True,
    "pcap": True,
    "pdf": True,
    "pem": True,
    "pl": True,
    "png": True,
    "po": True,
    "pot": True,
    "ps": True,
    "ps1": True,
    "py": True,
    "pyc": True,
    "pyo": True,
    "rb": True,
    "rtf": True,
    "rules": True,
    "sh": True,
    "spec": True,
    "ss": True,
    "svg": True,
    "swf": True,
    "sys": True,
    "tmpl": True,
    "ttf": True,
    "version": True,
    "woff": True,
    "xml": True,
    "xsd": True,
    "xsl": True,
}

# Whole filenames that we don't allow.  Keep in mind that we always squash
# to lowercase before comparison
BLACKLISTED_FILENAMES = {
    "args.txt": True,
    "audited": True,
    "dictionary.txt": True,
    "dir_info.txt": True,
    "done.txt": True,
    "generate_preview": True,
    "names.txt": True,
    "passwd": True,
    "pipeline_sets": True,
    "private-terms.txt": True,
    "public-terms.txt": True,
    "save": True,
    "splunkdj": True,
    "sudobash": True,
}

# Given a UNIX filename (as appears in a tarball) guess if it might be a
# valid pstack file, crashlog, etc.  This is just used because sometiems
# from support we get pstack tarballs that also contain scripts, diags,
# crashlogs, etc
def filename_looks_interesting(filename):
    if filename.endswith('/'):
        return False		# This is how directories appear in zip files
    x = filename.rfind('/')
    if x >= 0:
        filename = filename[x + 1:]
    squashed_filename = filename.lower()
    if len(filename_regexes) > 0:
        for regex in filename_regexes:
            if regex.search(filename) or regex.search(squashed_filename):
                return True
        return False
    p = squashed_filename.rfind('.')
    if p >= 0:
        if squashed_filename[p + 1:] in BLACKLISTED_EXTENSIONS:
            verbose("Ignoring file: \"%s\"" % filename)
            return False
    for bad_ending in [ "-manifest", ".conf.old", "-default", "searches.txt" ]:
        if squashed_filename.endswith(bad_ending):
            verbose("Ignoring file: \"%s\"" % filename)
            return False
    for bad_start in [ ".", "excluded_filelist", "systeminfo.", "maillog", "license", "authors", "copyright", "release-notes", "credits" ]:
        if squashed_filename.startswith(bad_start):
            verbose("Ignoring file: \"%s\"" % filename)
            return False
    for bad_substring in [ ".tar", ".tgz", ".zip", "ds_store", "readme", ".ps1.new" ]:
        if squashed_filename.find(bad_substring) >= 0:
            verbose("Ignoring file: \"%s\"" % filename)
            return False
    if squashed_filename == "core" or squashed_filename.startswith("core.") or squashed_filename.endswith(".core"):
        verbose("Ignoring file: \"%s\"" % filename)
        return False	# if they included a core dump in the file, we definitely should skip it
    if squashed_filename in BLACKLISTED_FILENAMES:
        verbose("Ignoring file: \"%s\"" % filename)
        return False	# if they included a core dump in the file, we definitely should skip it
    if squashed_filename.find(".log") >= 0 and not dot_log_filename_looks_interesting(squashed_filename):
        verbose("Ignoring file: \"%s\"" % filename)
        return False
    # At this point we'll accept it unless there are '-m !*' options to consider:
    for regex in ignore_regexes:
        if regex.search(filename) or regex.search(squashed_filename):
            return False
    return True

MATCH_SPLUNK_DIAG_DIRECTORY = re.compile("^diag-.*-2\\d\\d\\d-[01]\\d-[0123]\\d(_[012]\\d-[012345]\\d-[0123456])?\\d$")
# Sometimes diags get renamed to foo-diag or similar, so we don't anchor at the front of the filename
MATCH_SPLUNK_DIAG_TARBALL   = re.compile("diag-.*-2\\d\\d\\d-[01]\\d-[0123]\\d(_[012]\\d-[012345]\\d-[0123456]\\d)?\\.tar(\\.gz)?$")

# Yields a stream of objects describing each stack found in a directory
def read_pstack_directory(dirname, executable_path, pprof_tool):
    looks_like_splunk_log_directory = False
    if len(filename_regexes) == 0 and len(ignore_regexes) == 0:
        rp = os.path.abspath(dirname)
        if rp.endswith(os.path.sep + "log" + os.path.sep + "splunk"):
            looks_like_splunk_log_directory = True
        elif rp.endswith(os.path.sep + "log") and os.path.isfile(os.path.join(dirname, "..", "systeminfo.txt")):
            looks_like_splunk_log_directory = True	# probably inside a diag
        elif MATCH_SPLUNK_DIAG_DIRECTORY.search(os.path.split(rp)[1]):
            looks_like_splunk_log_directory = True
            dirname = os.path.join(dirname, "log")
    filename_filter = filename_looks_interesting
    # If we're reading something similar to a $SPLUNK_HOME/var/log/splunk
    # directory, just look for crashlogs by default.  Note that any use
    # of the -m option will disable this heuristic
    if looks_like_splunk_log_directory:
        verbose("Treating directory \"%s\" as a splunk log directory; only looking for crashlogs" % dirname)
        filename_filter = filename_looks_like_crashlog
    for filename in os.listdir(dirname):
        if filename_filter(filename):
            filename = os.path.join(dirname, filename)
            if os.path.isfile(filename):
                verbose("Reading file: \"%s\"" % filename, 2)
                for obj in read_from_filename(filename, executable_path, pprof_tool):
                    yield obj
                verbose_dot()
    verbose_dot_finish()

MATCH_UNIX_OR_WINDOWS_SEP = re.compile("[/\\\\]")

def filename_looks_like_crashlog_in_diag(filename):
    # We're probably always handed these filenames with unix separators,
    # but split on either just to be 100% sure
    pieces = re.split(MATCH_UNIX_OR_WINDOWS_SEP, filename)
    if len(pieces) < 2 or pieces[-2].lower() != "log":
        verbose("Ignoring non-crashlog file: \"%s\"" % filename, 2)
        return False
    return filename_looks_like_crashlog(pieces[-1])

# Reads the output of a pstack command, and yields a stream of objects describing each stack it find
def read_pstack_tarball(tar_filename, executable_path, pprof_tool):
    import tarfile
    filename_filter = filename_looks_interesting
    if len(filename_regexes) == 0 and len(ignore_regexes) == 0 and MATCH_SPLUNK_DIAG_TARBALL.search(os.path.split(tar_filename)[1]):
        verbose("Treating tarball \"%s\" as a splunk diag; only looking for crashlogs" % tar_filename)
        filename_filter = filename_looks_like_crashlog_in_diag
    tar = tarfile.open(tar_filename, "r:*")
    for tar_member in tar:
        if tar_member.isfile():
            if filename_filter(tar_member.name):
                verbose("Reading tarball member: \"%s\"" % tar_member.name, 2)
                for obj in read_from_filename(tar_member.name, executable_path, pprof_tool, tar.extractfile(tar_member)):
                    yield obj
                verbose_dot()
        tar.members = []	# Since we're reading the tarfile linearlly, nuke the cache to save RAM
    verbose_dot_finish()

# Similar for .zip files
def read_pstack_zipfile(zip_filename, executable_path, pprof_tool):
    import zipfile
    zf = zipfile.ZipFile(zip_filename, "r")
    for zip_member in zf.infolist():
        if filename_looks_interesting(zip_member.filename):
            verbose("Reading zipfile member: \"%s\"" % zip_member.filename, 2)
            for obj in read_from_filename(zip_member.filename, executable_path, pprof_tool, zf.open(zip_member)):
                yield obj
            verbose_dot()
    verbose_dot_finish()

# Read an assortment of files and directories
def read_pstack_files_and_dirs(paths, executable_path, pprof_tool):
    for p in paths:
        if p == "-":
            g = read_pstack_file_object(sys.stdin)
        elif os.path.isdir(p):
            g = read_pstack_directory(p, executable_path, pprof_tool)
        elif p.endswith(".tar") or p.endswith(".tar.gz") or p.endswith(".tar.bz2") or p.endswith(".tgz") or p.endswith(".tbz"):
            g = read_pstack_tarball(p, executable_path, pprof_tool)
        elif p.endswith(".zip") or p.endswith(".ZIP"):
            g = read_pstack_zipfile(p, executable_path, pprof_tool)
        else:
            g = read_from_filename(p, executable_path, pprof_tool)
        for obj in g:
            yield obj

# Any stacks that contain these functions are trimmed unless in '-I' mode:
FUNCTIONS_INDICATING_INACTIVITY = {
    "pthread_cond_wait": True,
    "pthread_cond_timedwait": True,
    "pthread_cond_timedwait_relative_np": True,
    "pthread_join": True,
    "sleep": True,
    "nanosleep": True,
    "pause": True,
    "sigsuspend": True,
    "epoll": True,
    "poll": True,
    "kevent": True,
    "select": True,
    "waitpid": True,
    # Some windows ones:
    "SleepEx": True,
    "ZwDelayExecution": True,
    "WSAWaitForMultipleEvents": True,
    "WaitForMultipleObjectsExImplementation": True,
    "WaitForMultipleObjectsEx": True,
    "ZwWaitForMultipleObjects": True,
    "SignalObjectAndWait": True,
    "NtSignalAndWaitForSingleObject": True,
    "NtWaitForWorkViaWorkerFactory": True,
    "WaitForSingleObjectEx": True,
    "NtWaitForSingleObject": True,
    "NtRemoveIoCompletion": True,
    "GetQueuedCompletionStatus": True,
    "NtWaitForMultipleObjects": True,
    "ZwWaitForWorkViaWorkerFactory": True,
    "NtWaitForMultipleObjects": True,
    "ZwWaitForWorkViaWorkerFactory": True,
    "NtWaitForAlertByThreadId": True,
    # Some solaris ones:
    "pollsys": True,
    "cond_wait": True,
    "cond_timedwait": True,
    "cond_wait_common": True,
    "cond_wait_queue": True,
    # Some AIX ones:
    "nsleep": True,
    "_p_nsleep": True,
    "_cond_wait_local": True,
    "_event_wait": True,
    "_event_sleep": True,
    "__fd_poll": True,
    # OS/X
    "__psynch_cvwait": True,
    "_pthread_cond_wait": True,
    "mach_msg_trap": True,
    "usleep": True,
    "__semwait_signal": True,
    "__semwait_signal_nocancel": True,
}

def stack_contains_function(obj, functions_to_find, inactive=False):
    n = len(obj["stack"])
    if n == 0:
        return False
    start_looking_at = 0
    for i in range(n):
        if obj["stack"][i] == "Thread::callMain":
            # Sometimes a mismatched library load will cause completely random
            # stuff before Thread::callMain; if we see callMain assume nothing
            # before it could be a blocking call!
            start_looking_at = i
            break
    for i in range(start_looking_at, n):
        e = obj["stack"][i]
        if e in functions_to_find:
            return True
        if e.startswith('_') and e[1:] in functions_to_find:
            return True
        if e.startswith('__') and e[2:] in functions_to_find:
            return True
        if inactive and e == "EventLoop::run" and i == n - 2 and obj["stack"][i + 1] in [ "syscall", "_fini"]:
            return True		# This is probably an epoll as well.  The _fini is just there if libc symbols weren't found
    return False

# Checks if the backtrace has any signs of being inactive (sleeping, epoll(), waiting on a cvar, ...)
def looks_active(obj):
    return not stack_contains_function(obj, FUNCTIONS_INDICATING_INACTIVITY, inactive=True)

def user_removed_function(obj):
    if len(FUNCTIONS_REMOVED_BY_USER) > 0:
        return stack_contains_function(obj, FUNCTIONS_REMOVED_BY_USER)
    return False

INTERNAL_LINUX_PTHREADS = re.compile("^_L_.*lock_\\d+$")	# internal locking functions look like "_L_cond_lock_886" etc
DATA_DOT_NUMBER = re.compile("^data\\.\\d+$")			# strings like "data.10540" sometimes show up when symbol resolution fails

# Functions that are cleaned if they appear in front of main()
MAIN_FUNCTION_SPAWNING_INFRASTRUCTURE = {
    "start": True,
    "_start": True,
    "__start": True,
    "__libc_start_main": True,
    # Sometimes if libc's symbols aren't found, things will show up as "_fini+BIG_NUMBER"
    "_fini": True,
}

# Functions that are cleaned if they're at the top of any thread
THREAD_SPAWNING_INFRASTRUCTURE = {
    "clone": True,
    "__clone": True,
    "start_thread": True,
    "_lwp_start": True,
    "_thr_setup": True,
    "_pthread_body": True,
    "thread_start": True,
    "_pthread_start": True,
    "_pthread_body": True,
    "RtlUserThreadStart": True,
    "beginthreadex": True,
    "_beginthreadex": True,
    "BaseThreadInitThunk": True,
    # For whatever reason, windows traces sometimes go endthreadex->beginthreadex
    # probably due to some symbol resolving problems
    "endthreadex": True,
    "_endthreadex": True,
}

# Functions that are cleaned if they appear after a particular one
CLEAN_IF_FOLLOWS = {
    # sleep() calls helper functions on some platforms; drop them for clarity
    "sleep": [ "nanosleep", "nsleep", "_p_nsleep" ],
    # Various OS implementing functions we see under pthread primitives
    "pthread_cond_wait": [ "cond_wait", "_cond_wait", "cond_wait_common", "cond_wait_queue", "__semwait_signal", "_cond_wait_local", "_event_wait", "_event_sleep" ],
    "pthread_cond_timedwait": [ "cond_timedwait", "_cond_timedwait", "cond_wait_common", "cond_wait_queue", "_cond_wait", "_cond_wait_local", "_event_wait", "_event_sleep" ],
    "mutex_lock": [ "mutex_lock_impl" ],
    # similar on windows
    "SleepEx": [ "ZwDelayExecution", "NtDelayExecution" ],
    "WSAWaitForMultipleEvents": [ "WaitForMultipleObjectsExImplementation", "WaitForMultipleObjectsEx", "ZwWaitForMultipleObjects"],
    "SignalObjectAndWait": [ "NtSignalAndWaitForSingleObject", "ZwSignalAndWaitForSingleObject" ],
    "WaitForSingleObjectEx": [ "NtWaitForSingleObject" ],
    # A few for Solaris/AIX:
    "poll": [ "pollsys", "__fd_poll" ],
    # OS/X
    "_pthread_cond_wait": [ "__psynch_cvwait" ],
    "usleep": [ "__semwait_signal" ],
    "nanosleep": [ "__semwait_signal" ],
}

# Returns a version of obj["stack"] that has been 'cleaned' of uninteresting
# functions for easier viewing
def cleaned_backtrace(obj):
    rv = []
    for e in obj["stack"]:
        if e == "Thread::callMain":
            # Throw away anything before callMain; often you get random
            # libc symbols if the libraries don't exactly match
            rv = []
            continue
        if len(rv) == 0:
            if e in THREAD_SPAWNING_INFRASTRUCTURE:
                continue
        else:
            if rv[-1] == "ReleaseMutex" and (e.startswith("NtRelease") or e.startswith("ZwRelease")):
                continue
            if "Zw" + rv[-1] == e:
                continue	# A common windows pattern: "WriteFile -> ZwWriteFile"
            if "Nt" + rv[-1] == e:
                continue	# Also handle cases like "SetEvent" -> "NtSetEvent"
            if rv[-1] in CLEAN_IF_FOLLOWS and e in CLEAN_IF_FOLLOWS[rv[-1]]:
                continue
            if rv[-1].startswith("pthread_") and (INTERNAL_LINUX_PTHREADS.search(e) or e.startswith("___lll_") or e.startswith("__lll_")):
                continue
            if e == "main":
                while len(rv) > 0 and rv[-1] in MAIN_FUNCTION_SPAWNING_INFRASTRUCTURE:
                    rv.pop()
            elif rv[-1] == e + "Implementation":
                rv.pop()	# A common windows pattern looks like "WriteFileImplementation -> WriteFile"; drop the first one
            elif e.startswith('_') and e.endswith("_sys") and e == rv[-1] + "_sys":
                continue	# HP/UX has _waitpid -> _waitpid_sys, etc
        if e.startswith("__GI_") and len(e) > 5:
            e = e[5:]	# __GI_strlen -> strlen
        if e.startswith("__mem") or e.startswith("__str"):
            # Turn functions like __memcmp_sse42 -> memcmp
            p = e.find('_', 2)
            if p >= 0:
                e = e[2:p]
            else:	# Also __memcpy -> memcpy
                e = e[2:]
        elif e.startswith("__libc_"):
            e = e[7:]
        elif e.startswith("__pthread_"):
            e = e[2:]
        elif e.startswith("_platform_mem") or e.startswith("_platform_str"):
            e = e[10:]	# _platform_memcmp -> memcmp
        elif DATA_DOT_NUMBER.search(e):
            continue
        elif e == "__mh_execute_header":	# These sometimes appear in OS/X backtraces
            continue
        elif e.endswith("__internal_alias"):	# An annoying thing that libxml2 does
            e = e[:-16]
        # Functions that appear twice in a row are sometimes recursive, or
        # sometimes are two functions that differ by prototype.  However,
        # a lot of times times they're just issues with the stacks captures.
        # Drop them for brevity's sake:
        if len(rv) == 0 or rv[-1] != e:
            rv.append(e)
    if len(rv) > 0 and rv[-1] == "lwp_park":
        rv.pop()	# Solaris has any parked LWP end on this function; not interesting
    return rv

def is_executable(filename):
    if not os.path.isfile(filename):
        return False
    if sys.platform.startswith("win"):
        return True
    return os.access(filename, os.X_OK)

# Find a tool in system path
def find_in_PATH(program, additional_paths=[]):
    s = {}
    paths = [ s.setdefault(p, p) for p in additional_paths + os.environ.get("PATH").split(os.pathsep) if p not in s ]
    for path in paths:
        f = os.path.join(path, program)
        if sys.platform.startswith("win") and f.find('/') == -1:
            f += ".EXE"
        if is_executable(f):
            return f
    return None

def find_perl5():
    for program in [ "perl5", "perl" ]:
        f = find_in_PATH(program)
        if f is not None:
            verbose("Using perl5 interpreter: %s" % f, 2)
            return f
    raise RuntimeError("Could not find perl5 interpreter to run external script")

# Search for a tool both in $SPLUNK_HOME/bin and the normal path
def find_tool(program, additional_paths=[], quiet=False):
    if "SPLUNK_HOME" in os.environ:
        splunk_home_bin = os.path.join(os.environ["SPLUNK_HOME"], "bin")
    else:
        # Fall back on guessing that it's in the same directory we are
        splunk_home_bin = os.path.split(os.path.abspath(__file__))[0]
    f = os.path.join(splunk_home_bin, program)
    if not is_executable(f):
        # Didn't find it, try looking in $PATH
        f = find_in_PATH(program, additional_paths)
        if f is None and not quiet:
            sys.stderr.write("Error: can't find \"%s\" tool" % program)
            if "SPLUNK_HOME" not in os.environ:
                if sys.platform.startswith("win"):
                    sys.stderr.write(" (maybe setting %SPLUNK_HOME% would help)")
                else:
                    sys.stderr.write(" (maybe setting $SPLUNK_HOME would help)")
            sys.stderr.write('\n')
    if f is not None:
        verbose("Using tool: %s" % f, 2)
    return f


# Any stacks that contain these functions are trimmed, populated by -R option
FUNCTIONS_REMOVED_BY_USER = {}

had_error = False

only_active = True
flamegraph_tool = None
flamegraph_options = []
flamegraph_has_explicit_title = False
clean_backtraces = True
sort_output = True
tids = []
live_provider = None
live_seconds = None
live_period = None
filename_regexes = []
ignore_regexes = []
executable_path = None
output_mode = ""	# -J for JSON
log_scale = False

PERIOD_SUFFIXES = [
    [ "ms", 1e3 ],
    [ "msec", 1e3 ],
    [ "us", 1e6 ],
    [ "usec", 1e6 ],
    [ "ns", 1e9 ],
    [ "nsec", 1e9 ],
    [ "s", 1 ],
    [ "sec", 1 ],
]

def parse_live_period(a):
    if a.startswith('/'):
        return 1.0 / float(a[1:])
    if a.endswith("hz") or a.endswith("HZ"):
        return 1.0 / float(a[:-2])
    for suffix in PERIOD_SUFFIXES:
        if a.endswith(suffix[0]):
            return float(a[:-len(suffix[0])]) / suffix[1]
    return float(a)

import getopt

# For convinience, you can pass in any flamegraph.pl option directly when outputting flamegraphs
FLAMEGRAPH_PL_OPTIONS_WITH_VALUE = [
    "fonttype",
    "width",
    "height",
    "encoding",
    "fontsize",
    "fontwidth",
    "minwidth",
    "title",
    "nametype",
    "countname",
    "nameattr",
    "total",
    "factor",
    "colors",
]
FLAMEGRAPH_PL_OPTIONS_WITHOUT_VALUE = [
    "hash",
    "cp",
    "reverse",
    "inverted",
    "negate",
]

try:
    opts, args = getopt.getopt(sys.argv[1:], "vFJIdut:L:s:p:m:E:lR:", [i + '=' for i in FLAMEGRAPH_PL_OPTIONS_WITH_VALUE] + FLAMEGRAPH_PL_OPTIONS_WITHOUT_VALUE + [ "help" ])
    for o, a in opts:
        if o == '-v':
            verbose_level += 1
        elif o == '-F':
            flamegraph_script = find_tool("flamegraph.pl")
            if flamegraph_script is None:
                had_error = True
            else:
                flamegraph_tool = [ find_perl5(), flamegraph_script ]
            sort_output = False
        elif o == '-J':
            import json
            output_mode = o
        elif o == '-I':
            only_active = False
        elif o == '-d':
            clean_backtraces = False
        elif o == '-u':
            sort_output = False
        elif o == '-t':
            tids.append(a)
        elif o == '-L':
            if live_provider is not None and live_provider != a:
                sys.stderr.write("-L option should not be specified multiple times\n")
                had_error = True
            live_provider = a
        elif o == '-s':
            v = float(a)
            if live_seconds is not None and live_seconds != v:
                sys.stderr.write("-s option should not be specified multiple times\n")
                had_error = True
            live_seconds = v
        elif o == '-p':
            v = parse_live_period(a)
            if live_period is not None and live_period != v:
                sys.stderr.write("-p option should not be specified multiple times\n")
                had_error = True
            live_period = v
        elif o == '-m':
            import fnmatch
            if a.startswith('!'):
                ignore_regexes.append(re.compile(fnmatch.translate(a[1:])))
            else:
                filename_regexes.append(re.compile(fnmatch.translate(a)))
        elif o in ["--" + i for i in FLAMEGRAPH_PL_OPTIONS_WITH_VALUE]:
            flamegraph_options.append(o + '=' + a)
            if o == "--title":
                flamegraph_has_explicit_title = True
        elif o in ["--" + i for i in FLAMEGRAPH_PL_OPTIONS_WITHOUT_VALUE]:
            flamegraph_options.append(o)
        elif o == '-E':
            executable_path = a
        elif o == '-l':
            log_scale = True
        elif o == "-R":
             for func in a.split(','):
                 FUNCTIONS_REMOVED_BY_USER[func] = True
        elif o == "--help":
            sys.stdout.write(USAGE)
            sys.exit(0)
except getopt.GetoptError:
    sys.stderr.write(USAGE)
    sys.exit(8)
except ValueError:
    sys.stderr.write(USAGE)
    sys.exit(8)

if len(args) == 0:
    if sys.stdin.isatty():
        sys.stderr.write(USAGE)
        sys.exit(8)
    args = [ "-" ]	# work as a filter

# Get the initial line from a pid file
def read_pidfile(filename):
    f = open(filename)
    first_line = f.readline()
    f.close()
    try:
        pid = int(first_line)
    except ValueError:
        sys.stderr.write("Couldn't read pid from \"" + filename + "\"\n\n")
        raise
    verbose("Read pid %u from file \"%s\"" % (pid, filename))
    return pid


class LiveProvider(object):
    """Abstract base class for live stack call dump providers."""
    def isAvailable(self):
        if hasattr(self, "_isAvailable"):
            return self._isAvailable
        for n in self.names():
            self.fullPath = find_tool(n, self.additionalPathsToSearch(), True)
            if self.fullPath:
                break
        self._isAvailable = self.fullPath is not None
        return self._isAvailable

    def run(self, pid, seconds, period, tids):
        if not self.isAvailable():
            binDescr = self.names()[0]
            if len(self.names()) == 1:
                binDescr = "binary `" + self.names()[0] + "`"
            else:
                binDescr = "binaries: `" + self.names().join("`, or `") + "`"
            sys.stderr.write("Can't locate " + binDescr)
            sys.exit(1)
        args = self._buildArgs(self.fullPath, pid, seconds, period, tids)
        import subprocess
        stderr = None
        if self._capturesStderr():
            stderr = subprocess.PIPE
        verbose("Running: " + ' '.join(args))
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=stderr)
        stderr_thread = None
        if self._capturesStderr():
            stderr_thread = stderr_capturing_thread(proc.stderr)
            global captured_stderr_from_child
        for obj in read_pstack_file_object(proc.stdout):
            yield obj
        proc.wait()
        if stderr_thread is not None:
            stderr_thread.join()
            if sys.version_info >= (3, 0):
                captured_stderr_from_child = captured_stderr_from_child.decode()
            self._postprocessStderr(proc.returncode, captured_stderr_from_child)

    def additionalPathsToSearch(self):
        return []

    def names(self):
        """Abstract method
        return list of possible binary names for this object
        """
        return []

    def _buildArgs(self, binPath, pid, seconds, period, tids):
        """Abstract method
        return list of command-line arguments like what subprocess.Popen() wants
        """
        return []

    def _capturesStderr(self):
        """Abstract method
        return true if stderr should be captured and only output if the
        process returns non-zero
        """
        return False

    def _postprocessStderr(self, return_code, stderr):
        if return_code != 0:
            verbose(self.fullPath + " exited with status code %d" % return_code)
            sys.stderr.write(stderr)
            global exit_code
            if exit_code == 0:
                 exit_code = return_code

class UnixStack(LiveProvider):
    def _buildArgs(self, binPath, pid, seconds, period, tids):
        return [ binPath, str(pid) ]

    def run(self, pid, seconds, period, tids):
        if period is None:
            # Aim for 50ish pstacks, but clamp within some limits
            period = seconds / 50
            if period < 0.25:
                period = 0.25
            if period > 3:
                period = 3

        import time, random
        now = time.time()
        start_time = now
        next_scheduled = start_time
        end_time = start_time + seconds
        # In order to make sure our pstacking grabbing isn't syncronized with
        # any periodic action in the target process, we add a little random jitter
        jitter = period / 20
        printed_progress_message = False
        if verbose_level > 0:
            msg = "Collecting stacks from PID %u for %.3f second" % (pid, seconds)
            if seconds != 1:
                msg += 's'
            msg += ", one every %.3f second" % period
            if period != 1:
                msg += 's'
            verbose(msg)
        while True:
            for obj in LiveProvider.run(self, pid, seconds, period, tids):
                yield obj
            if verbose_level > 0:
                ratio = (time.time() - start_time) / seconds
                if ratio > 1:
                    ratio = 1
                verbose_without_newline("\r  [%6.2f%%]" % (ratio * 100))
                printed_progress_message = True
            next_scheduled += period
            target_time = next_scheduled + random.uniform(-jitter, jitter)
            now = time.time()
            # we may overrun end_time and it is intentional: if each collection
            # takes so long we can't meet the target end time, we'll simply
            # reduce sleep time (or not sleep at all)
            if target_time > end_time or target_time < start_time:
                break
            if target_time > now:
                time.sleep(target_time - now)
        if printed_progress_message:
            sys.stderr.write("\r  [DONE]        ")
            verbose_dot_finish()

    def _capturesStderr(self):
        return False

class Pstack(UnixStack):
    def names(self):
        return ["pstack"]

    def additionalPathsToSearch(self):
        return ["/usr/proc/bin", "/usr/ccs/bin"]

class Procstack(UnixStack):
    def names(self):
        return ["procstack"]

EUSTACK_ERRORS_IGNORED = re.compile("no matching address range$", re.MULTILINE)
class Eustack(UnixStack):
    def names(self):
        return ["eu-stack"]

    def _buildArgs(self, binPath, pid, seconds, period, tids):
        args = [ binPath, "-p" ]
        if len(tids)!=1:
            args.append(str(pid))
        else:
            args.extend([str(tids[0]), "-1"])
        return args

    def _capturesStderr(self):
        return True

    def _postprocessStderr(self, return_code, stderr):
        lines = stderr.split("\n")
        for l in lines:
            if l and not EUSTACK_ERRORS_IGNORED.search(l):
                break
        else:
            return_code = 0
        LiveProvider._postprocessStderr(self, return_code, stderr)

class Dtrace(LiveProvider):
    def names(self):
        return ["dtrace"]

    def _buildArgs(self, binPath, pid, seconds, period, tids):
        if period is None:
            # Dtrace has fairly low impact.  97 samples per second is a
            # fairly common value.  (A value of 100 might accidentally "mesh"
            # with a periodic activity of the process)
            period = 1.0 / 97
        if seconds == int(seconds):
            tick_string = "%usec" % seconds
        elif 1e3 * seconds == int(1e3 * seconds):
            tick_string = "%umsec" % (seconds * 1e3)
        else:
            tick_string = "%uusec" % int(round(seconds * 1e6))
        args = [ binPath, "-q", "-p", str(pid), "-x", "ustackframes=100", "-n",
            "profile-%unsec /pid == %u/ { @[ustack()] = count(); } tick-%s { exit(0); }"
                % (int(round(period * 1e9)), pid, tick_string) ]
        if os.geteuid() > 0:
            sudo_binary = find_in_PATH("sudo", ["/usr/bin", "/bin"])
            if sudo_binary is None:
                sys.stderr.write("Not running as root, dtrace probably won't work!\n")
            else:
                verbose("Not running as root, assuming sudo is required to run dtrace")
                args.insert(0, sudo_binary)
        return args

    def _capturesStderr(self):
        return True

OSX_SAMPLE_WROTE_TO_FILE = re.compile("written to file (/tmp/.*\\.sample.*\\.txt)")
class OsxSample(LiveProvider):
    def names(self):
        return ["sample"]

    def additionalPathsToSearch(self):
        return ["/usr/sbin", "/usr/bin"]

    def _buildArgs(self, binPath, pid, seconds, period, tids):
        if period is None:
            # Default period is 1ms, so I guess it should be pretty efficient
            # We go a little less aggressive at 3ms
            period = 0.003
        args = [ binPath, str(pid), str(int(round(seconds))), str(int(round(period * 1000) + 0.5)) ]
        return args

    def _capturesStderr(self):
        return True

    def _postprocessStderr(self, return_code, stderr):
        LiveProvider._postprocessStderr(self, return_code, stderr)
        # Annoyingly, the "sample" command always writes to a /tmp file even
        # when it's outputting to stdout.  It does tell us where that file is
        # in its stderr messages though.
        m = OSX_SAMPLE_WROTE_TO_FILE.search(stderr)
        if m:
            verbose("Removing left-over file \"%s\"" % m.group(1))
            os.unlink(m.group(1))

PROVIDERS = {
    "Darwin": [ OsxSample(), Dtrace() ],
    "auto": [ Eustack(), Pstack(), Procstack() ]
}

live_pid = None
generator = None
pprof_tool = None

if len(args) == 1:
    try:
        live_pid = int(args[0])
    except ValueError:
        if args[0].endswith(".pid"):
             live_pid = read_pidfile(args[0])
        elif args[0] != "-" and os.path.isdir(args[0]) and os.path.isdir(os.path.join(args[0], "var", "run", "splunk")):
             live_pid = read_pidfile(os.path.join(args[0], "var", "run", "splunk", "splunkd.pid"))

if live_pid is None:
    if live_provider is not None:
        sys.stderr.write("ERROR: -L option not valid when not capturing live results\n")
        had_error = True
    if live_seconds is not None:
        sys.stderr.write("ERROR: -s option not valid when not capturing live results\n")
        had_error = True
    if live_period is not None:
        sys.stderr.write("ERROR: -p option not valid when not capturing live results\n")
        had_error = True
    has_prof_file = False
    for arg in args:
        if arg.endswith(".prof"):
            has_prof_file = True
            break
    if has_prof_file:
        if executable_path is None:
            sys.stderr.write("ERROR: -E option is required when reading .prof output\n")
            had_error = True
        pprof_tool = find_tool("pprof")
        if pprof_tool is None:
            had_error = True
else:
    if len(filename_regexes) > 0 or len(ignore_regexes) > 0:
        sys.stderr.write("ERROR: -m option not valid when capturing live results\n")
        had_error = True

    providers = []
    provider = None
    if live_provider is None or live_provider == "auto":
        import platform
        if platform.system() in PROVIDERS:
            providers = PROVIDERS[platform.system()]
        else:
            providers = PROVIDERS["auto"]
    else:
        for prov in PROVIDERS.values():
            for p in prov:
                if live_provider in p.names():
                    providers.append(p)
    for p in providers:
        if p.isAvailable():
            provider = p
            break
    if provider is None:
        providers_tested = []
        for p in providers:
            providers_tested += p.names()
        if live_provider and not providers_tested:
            providers_tested.append(live_provider)
        sys.stderr.write("ERROR: could not find a valid tool to capture live stack traces (tried `%s`)\n" % "`, `".join(providers_tested))
        had_error = True
    else:
        verbose("Using %s to capture live stack traces on this platform (use -L to override)" % provider.names()[0])

    if live_seconds is None:
        live_seconds = 20

if output_mode != "" and flamegraph_tool is not None:
    sys.stderr.write("ERROR: -F and -J options not meaningful together\n")
    had_error = True

if flamegraph_tool is None:
    for opt in flamegraph_options:
        sys.stderr.write("ERROR: %s option not meaningful when -F not specified\n" % opt.split('=')[0])
        had_error = True
elif not flamegraph_has_explicit_title:
    added_generated_title = False
    if live_pid is None:
        if len(args) == 1 and args[0] != "-":
            flamegraph_options.append("--title=" + os.path.split(args[0])[1])
            added_generated_title = True
    else:
        import time
        flamegraph_options.append("--title=pid %u at %s" % (live_pid, time.strftime("%Y-%m-%d %H:%M:%S %Z")))
        added_generated_title = True
    if added_generated_title and log_scale:
        flamegraph_options[-1] += " (log scale)"

if had_error:
    sys.stderr.write(USAGE)
    sys.exit(8)

if live_pid is None:
    generator = read_pstack_files_and_dirs(args, executable_path, pprof_tool)
else:
    try:
        os.kill(live_pid, 0)
    except:
        sys.stderr.write("ERROR: can't access pid %u\n\n" % live_pid)
        raise
    generator = provider.run(live_pid, live_seconds, live_period, tids)

unique_stacks = {}
stack_is_active = {}	# only needed in -J mode
# The next four are just used in verbose mode:
collected_stack_count = 0
filtered_by_thread_count = 0
active_looking_stacks = 0
unique_tids = {}

exit_code = 0
try:
    for obj in generator:
        count = 1
        if "count" in obj:
            count = int(obj["count"])
        collected_stack_count += count
        if "tid" in obj:
            if verbose_level > 0:
                unique_tids[obj["tid"]] = True
            if len(tids) > 0 and obj["tid"] not in tids:
                filtered_by_thread_count += count
                continue
        if user_removed_function(obj):
            continue
        is_active = True
        if only_active:
            if not looks_active(obj):
                continue
            active_looking_stacks += count
        elif (verbose_level > 0 or output_mode == "-J"): # skip even computing is_active if nobody will care
            is_active = looks_active(obj)
            if is_active:
                active_looking_stacks += count
        # Render the stacktrace in a format compatible with the flamegraph stackcollapse.pl script
        if clean_backtraces:
            s = ';'.join(cleaned_backtrace(obj))
        else:
            s = ';'.join(obj["stack"])
        if output_mode == "-J":
            stack_is_active[s] = is_active
        if s in unique_stacks:
            unique_stacks[s] += count
        else:
            unique_stacks[s] = count
except KeyboardInterrupt:
    if not unique_stacks:
        raise		# If we haven't collected anything, we might as well raise the error
    exit_code = 1	# Otherwise, output anything we've got so far but still return with an error

if verbose_level > 0:
    msg = "Collected %u stack" % collected_stack_count
    if collected_stack_count != 1:
        msg += 's'
    if len(unique_tids) > 1:
        msg += " from %u unique threads" % len(unique_tids)
    if filtered_by_thread_count > 0:
        msg += ", and filtered %u of them.  Of the remaining %u" % (filtered_by_thread_count, collected_stack_count - filtered_by_thread_count)
    msg += ", %u stack" % active_looking_stacks
    if active_looking_stacks != 1:
        msg += 's'
    msg += " looked active.  %u emitted stack" % len(unique_stacks)
    if len(unique_stacks) != 1:
        msg += 's'
    msg += " were unique."
    verbose(msg)

if log_scale:
    import math
    for stack, count in unique_stacks.items():
        unique_stacks[stack] = int(math.ceil(math.log(count, 2)))

output_fh = sys.stdout
flamegraph_process = None

if flamegraph_tool is not None:
    import subprocess
    flamegraph_process = subprocess.Popen(flamegraph_tool + flamegraph_options, stdin=subprocess.PIPE)
    output_fh = flamegraph_process.stdin
    if sys.version_info >= (3, 0):
        import codecs
        output_fh = codecs.getwriter("utf-8")(output_fh)

def write_ascii_flamegraph_style_item(output_fh, count, stack):
    output_fh.write("%s %u\n" % (stack, count))

def write_json_item(output_fh, count, stack):
    global stack_is_active
    output_fh.write("{\"count\":%u,\"stack\":[" % count)
    first = True
    for s in stack.split(';'):
        if first:
            first = False
        else:
            output_fh.write(",")
        output_fh.write(json.dumps(s))
    output_fh.write("],\"active\":")
    if stack_is_active[stack]:
        output_fh.write("true")
    else:
        output_fh.write("false")
    output_fh.write("}\n")

write_item = write_ascii_flamegraph_style_item
if output_mode == "-J":
   write_item = write_json_item

try:
    if sort_output:
        for x in sorted(unique_stacks, key = unique_stacks.get, reverse = True):
            write_item(output_fh, unique_stacks[x], x)
    else:
        for x in unique_stacks:
            write_item(output_fh, unique_stacks[x], x)
    sys.stdout.flush()		# make sure we get any EPIPE beforewe exit the loop
except IOError as e:
    if flamegraph_process is None:
        import errno
        if e.errno == errno.EPIPE:
            output_fh.close()
            sys.exit(exit_code)

if flamegraph_process is not None:
    flamegraph_process.stdin.close()
    flamegraph_process.wait()
    if flamegraph_process.returncode != 0:
        verbose("flamegraph.pl exited with status code %d" % flamegraph_process.returncode)
        if exit_code == 0:
            exit_code = flamegraph_process.returncode

sys.exit(exit_code)
