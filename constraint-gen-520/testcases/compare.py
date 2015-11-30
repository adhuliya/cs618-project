#!/usr/bin/python3

import sys
import re
import os

def extract_file_content (filename):
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

def format_content (content):
    fmt_content = []
    tmp = []
    for pdata in content:
        tmp = []
        tmp.append (pdata[0])
        match = re.search (r"Parsed data: index (.*), bool (.*), block (.*?),", pdata[1]);
        tmp.append ([pdata[1], match.group (1), match.group (2), match.group (3)])
        if pdata[0] == 0:
            # use of a variable
            for i in range (2, len(pdata)):
                match = re.search(r"Var id (.*), name (.*), offset (.*)", pdata[i])
                name = process_name (match.group (2))
                tmp.append ([pdata[i], match.group (1), name, match.group (3)])
        elif pdata[0] == 1:
            # an assignment
            match = re.search (r"assignment index=(.*)", pdata[2])
            tmp.append ([pdata[2], match.group (1)])

            ttt = ("(LHS: variable id (.*), ptr_arith=(.*), offset (.*),"
                    " type (.*), name (.*),) (RHS: variable id (.*), ptr_arith=(.*),"
                    " offset (.*), type (.*), name (.*))")
            match = re.search (ttt, pdata[3])

            name_lhs = process_name (match.group (6))
            name_rhs = process_name (match.group (12))

            tmp.append ([match.group (1), match.group (2), match.group (3),  
                match.group (4), match.group (5), name_lhs])
            tmp.append ([match.group (7), match.group (8), match.group (9), 
                match.group (10), match.group (11), name_rhs])

        fmt_content.append (tmp)

    # for fmt in fmt_content:
    #     print (fmt)
    #     print ()


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
    content1 = extract_file_content (file1)
    content2 = extract_file_content (file2)

    # write the extracted content to new files
    write_to_file (name=file1, suffix="-new", content=content1)
    write_to_file (name=file2, suffix="-new", content=content2)

    # format the content for adequate automatic comparison
    fmt_content1 = format_content (content1)
    # print ("################################################################")
    fmt_content2 = format_content (content2)

    # compare the contents 
    # returns true if equal
    isequal = compare (fmt_content1, fmt_content2)

    if not isequal:
        print ("Found: Difference in Constraints")


if __name__ == '__main__':
    main()
