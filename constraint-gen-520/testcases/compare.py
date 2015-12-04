#!/usr/bin/python3

"""
This program extracts the constraints generated only for the main() in C.

It has been customized for GCC 4.7.2 version of constraint-gen code.

It extracts the Constraint and the gimple stmt it corresponds to.

TODO: separate the comparison part from the constraint enumeration part.
As they are not compatible.
"""

import sys
import re
import os

class AssignConstr:
    def __init__ (self, index=-1, lhs=True, varid=-1, ptr_arith=False, 
            offset=0, usetype=0, name='--'):
        self.index = index
        self.lhs = lhs
        self.ptr_arith = ptr_arith
        self.usetype = usetype

        self.varinfo = VarInfo (varid, offset, name)


    def __eq__ (self, other):
        result = self.ptr_arith == other.prt_arith
        result = result and self.offset == other.offset
        result = result and self.usetype == self.usetype
        
        return result

    def __hash__ (self):
        hsh = 0
        if self.ptr_arith: 
            hsh += 1 
        hsh += self.offset
        hsh += usetype

        return hsh

    def __str__ (self):
        lhs = 'RHS'
        if self.lhs: lhs = 'LHS'
        return "(AssignConstr: {2}, {0}, {1.usetype}, {1.ptr_arith})".format (
                str(self.varinfo), self, lhs)

class VarInfo:
    def __init__ (self, varid=-1, offset="", name='--'):
        self.varid = varid
        self.offset = offset
        self.name = name

    def __eq__ (self, other):
        if not isinstance(other, VarInfo): return NotImplemented

        return (self.varid == other.varid and self.offset == other.offset
                    and self.name == other.name)

    def __str__ (self):
        return "(VarInfo: {0.varid}, {0.offset}, {0.name})".format (self)


class ParsedData:
    def __init__ (self, index=-1, assign=True, block=-1):
        self.index = index
        self.assign = assign
        self.block = block

        self.pdata = []
        self.stmt = ''      #gimple statement

        if assign:
            self.asgnindex = -1
            self.lhs = AssignConstr ()
            self.rhs = AssignConstr ()
            self.variables = None
        else:
            self.varinfos = []
            self.lhs = None
            self.rhn = None

    def __str__ (self):
        lst = []
        out = "(ParsedData:[{}] {}, {}, {}:\n{})"
        if self.assign:
            lst.append (str (self.lhs))
            lst.append (str (self.rhs))
        else:
            for vi in self.varinfos:
                lst.append (str (vi))

        return out.format (self.stmt, self.index, self.assign, self.block, 
                "\n".join (lst))

def extract_blk_content (filename):
    """
    Needs main to be defined! Only extracts from main()
    Extract the gimple statements from the result.233i.heap file generated 
    from GCC 4.7.2 and store the statements in a dictionary with key as blockid.

    Returns a dictionary: key : blkid, value: single gimple statement
    """

    blkdict = dict()
    blkid = -1
    inblk = False
    fc = ''

    with open (filename, encoding='utf-8') as f:
        fc = f.read()

    match= re.search (r'main \(\)\s+{(?P<main>.*?)\s+}\n', fc, re.DOTALL)

    main = match.group ('main')

    # print (main) # delit

    lines = main.splitlines ()

    for line in lines:
        match = re.search (r'<bb\s+?(\d+)>', line)
        if match:
            blkid = int (match.group (1))
            inblk = True
        else:
            if inblk:
                blkdict[blkid] = line.strip()
                inblk = False

    return blkdict

def extract_constraints (filename):
    """
    Reformat the file content, such that the file comparison can be straight
    forward with a tool like diff (if found feasible later)
    """
    with open (filename) as f:
        content = f.read()

    lines = content.splitlines()

    count = 0
    typeofdata = 2    # 2=default, 1=Assignment Parsed data, 0=Var Parsed data
    parsed_data = []
    tmp = []
    for line in lines:
        if line.startswith ("Parsed data:"):
            count = 0
            tmp = []
            parsed_data.append (tmp)
            match = re.search (r"Parsed data: index (.*), bool (.*), block (.*),", line);
            typeofdata = int (match.group (2))
            tmp.append (typeofdata)
            tmp.append (line)
        elif typeofdata == 0:
            if line.startswith ("Var id"):
                tmp.append (line)
            else:
                typeofdata = 2
        elif typeofdata == 1:
            count += 1
            if count <= 2:
                tmp.append (line)
            else:
                count = 0
                typeofdata = 2

    return parsed_data


def write_to_file (name, suffix, content):
    with open (name + suffix, "w") as f:
        for d1 in content:
            for d2 in d1:
                print (d2, file=f)

def process_name (name):
    """
    Makes the variable name uniform to let it be compared.
    """
    p_name = name
    if name.count ("_") > 0 and not name.startswith ("_"):
        p_name = name.split ("_")[0]
    if name.startswith ("_") or name.count (".") > 0:
        p_name = "temp"
    return p_name

def format_content (parsedcontent, blkdict):
    fmt_content = []
    pd = ParsedData ()

    blkid = 0

    for pdata in parsedcontent:
        m = re.search (r"Parsed data: index (\d+), bool (\d+), block (\d+),", pdata[1]);
        pd = ParsedData (index=int(m.group (1)), assign=bool(int(m.group(2))), 
                block=int(m.group(3)))
        pd.pdata.append (pdata[1])
        pd.stmt = blkdict[pd.block]

        if pd.block < blkid:
            break
        else:
            blkid = pd.block

        if not pd.assign:
            # use of a variable
            for i in range (2, len(pdata)):
                m = re.search(r"Var id (\d+), name (.*), offset (\d+)", pdata[i])
                name = process_name (m.group (2))
                pd.varinfos.append (VarInfo (varid=int(m.group (1)), 
                    offset=int(m.group (3)), name=name))
                pd.pdata.append (pdata[i])

        else:
            # an assignment
            m = re.search (r"assignment index=(\d+)", pdata[2])
            pd.asgnindex = int(m.group (1))

            ttt = ("(LHS: variable id (\d+), ptr_arith=(\d+), offset (.*?),"
                    " type (\d+), name (.*),) (RHS: variable id (\d+), ptr_arith=(\d+),"
                    " offset (.*?), type (\d+), name (.*))")
            m = re.search (ttt, pdata[3])

            # store LHS
            pd.pdata.append (m.group(1))
            pd.lhs.varinfo = VarInfo (varid=int(m.group(2)),
                offset=m.group(4), name=process_name(m.group(6)))
            pd.lhs.lhs = True
            pd.lhs.ptr_arith = bool (m.group (3))
            pd.lhs.usetype = int (m.group (5))

            # store RHS
            pd.pdata.append (m.group(7))
            pd.rhs.varinfo = VarInfo (varid=int(m.group(8)),
                offset=m.group(10), name=process_name(m.group(12)))
            pd.rhs.lhs = False
            pd.rhs.ptr_arith = bool (m.group (9))
            pd.rhs.usetype = int (m.group (11))

        fmt_content.append (pd)

    for pd in fmt_content:
        print (pd)
        print ()

    return fmt_content

def compare_p (pdata1, pdata2):
    isequal = True
    msg = []

    # compare the basic information
    if pdata1[0] != pdata2[0]:
        msg.append ("Assignment vs Usage Constraint Mismatch")
        isequal = False
    # if pdata1[1][1] != pdata2[1][1]:
    #     msg.append ("Parsed Data: Index Mismatch")
    #     isequal = False
    if pdata1[1][3] != pdata2[1][3]:
        msg.append ("Parsed Data: Block ID Mismatch")
        isequal = False

    if isequal:
        if pdata1[0] == 0: # and pdata2[0] == 0:
            if len (pdata1) != len (pdata2):
                msg.append ("No. of variables mismatch")
                isequal = False
            else:
                for i in range (2, len (pdata1)):
                    if pdata1[i][2] != pdata2[i][2]:
                        msg.append ("Variable name mismatch", i)
                        isequal = False
                    if pdata1[i][3] != pdata2[i][3]:
                        msg.append ("Variable offset mismatch", i)
                        isequal = False

        elif pdata1[0] == 1: # and pdata2[0] == 1:
            # if pdata1[2][1] != pdata2[2][1]:
            #     msg.append ("Assignment index mismatch")
            #     isequal = False
            if pdata1[3][2] != pdata2[3][2]:
                msg.append ("LHS ptr_arith mismatch")
                isequal = False
            if pdata1[3][3] != pdata2[3][3]:
                msg.append ("LHS offset mismatch")
                isequal = False
            if pdata1[3][4] != pdata2[3][4]:
                msg.append ("LHS type mismatch")
                isequal = False
            if pdata1[3][5] != pdata2[3][5]:
                msg.append ("LHS name mismatch")
                isequal = False
            if pdata1[4][2] != pdata2[4][2]:
                msg.append ("RHS ptr_arith mismatch")
                isequal = False
            if pdata1[4][3] != pdata2[4][3]:
                msg.append ("RHS offset mismatch")
                isequal = False
            if pdata1[4][4] != pdata2[4][4]:
                msg.append ("RHS type mismatch")
                isequal = False
            if pdata1[4][5] != pdata2[4][5]:
                msg.append ("RHS name mismatch")
                isequal = False

    if not isequal:
        print_mismatch (os.linesep.join (msg), pdata1, pdata2)

    return isequal


def print_mismatch (msg, pdata1, pdata2):
    print ("================================================================")
    print ("Message(s):")
    print (msg)
    print ("================================================================")
    print_pdata (pdata1)
    print ()
    print_pdata (pdata2)
    print ("================================================================")
    print ()


def print_pdata (pdata):
    if pdata[0] == 0:
        print (pdata[1][0])
        for i in range (2, len(pdata)):
            print (pdata[i][0])
    elif pdata[0] == 1:
        print (pdata[1][0])
        print (pdata[2][0])
        print (pdata[3][0])
        print (pdata[4][0])

def compare (fmt_content1, fmt_content2):
    isequal = True

    if len(fmt_content1) != len(fmt_content2):
        isequal = False
        print ("Number of constraints differ! Aborting.")
        print ("First has", len(fmt_content1), ", Second has", len(fmt_content2))
    else:
        print ("Match: Number of contraints:", len (fmt_content1))
        for (pdata1, pdata2) in zip (fmt_content1, fmt_content2):
            compare_p (pdata1, pdata2)

    return isequal


def main():
    file1 = ""
    file2 = ""
    if len(sys.argv) == 3:
        file1 = sys.argv[1]
        file2 = sys.argv[2]
    else:
        print ("Usage: ./compare.py <file1> <file2>")

    # extract the relevant portions from the files
    constraints1 = extract_constraints (file1)
    constraints2 = extract_constraints (file2)

    blk_content1 = extract_blk_content (file1)
    #blk_content2 = extract_blk_content (file2)

    # write the extracted content to new files
    write_to_file (name=file1, suffix="-new", content=constraints1)
    write_to_file (name=file2, suffix="-new", content=constraints2)

    # format the content for adequate automatic comparison
    fmt_content1 = format_content (constraints1, blk_content1)
    # print ("################################################################")
    #fmt_content2 = format_content (constraints2)

    # compare the contents 
    # returns true if equal
    # isequal = compare (fmt_content1, fmt_content2)

    # if not isequal:
    #     print ("Found: Difference in Constraints")


if __name__ == '__main__':
    main()
