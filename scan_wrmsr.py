import idc
import idaapi
import idautils
import sys
import os
import ida_allins
import ida_hexrays
import ida_pro 
import ida_lines 
from csv import writer 

#replace with your own globally writeable file. 
csv = "C:\\Users\\John\\Documents\\analysis_results\\msr_entries.csv"

def append_row(row):

    with open(csv, 'a+', newline='') as write_obj:
        csv_writer = writer(write_obj)
        csv_writer.writerow(row)


ECX = 1 

wrmsr_db = []


filename = idaapi.get_input_file_path()

print("Analyzing " + filename)

for ea in Functions():
    #Keep function ea
    fea = ea
    f = ida_funcs.get_func(ea)

    for ea in Heads(f.start_ea, f.end_ea):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)

        if insn.itype == ida_allins.NN_wrmsr:
            print("Wrmsr instruction at %x" % ea)

            print("Attempting backtrace to last ECX")
            steps = 10
            addr = ea 

            constant = False

            while steps > 0: 
                addr = idc.PrevHead(addr)
                this_insn = idaapi.insn_t()
                this_len =  idaapi.decode_insn(this_insn, addr)


                #Check if the first operand is a register. 
                if this_insn.ops[0].type == ida_ua.o_reg: 
                    if this_insn.ops[0].reg == ECX:
                        print("Found proximal usage of ECX, checking value type of rh operand")

                        if this_insn.ops[1].type == ida_ua.o_mem:
                            print("wrmsr takes a data value from memory at: %x" % insn.ops[1].value)
                        elif this_insn.ops[1].type == ida_ua.o_reg:
                            print("wrmsr takes a data value from another register at: %x" % insn.ops[1].value)
                        elif this_insn.ops[1].type == ida_ua.o_mem:
                            print("wrmsr takes a data value from a known memory address at: %x" % insn.ops[1].value)
                        elif this_insn.ops[1].type == ida_ua.o_phrase:
                            print("wrmsr takes a data value from a pointer to an address: %x" % insn.ops[1].value)
                        elif this_insn.ops[1].type == ida_ua.o_displ:
                            print("wrmsr takes a data value from a pointer to an address: %x" % insn.ops[1].value)
                        elif this_insn.ops[1].type == ida_ua.o_imm:
                            print("wrmsr takes a data value from a constant (likely not useful!): %x" % insn.ops[1].value)
                            constant = True 

                steps = steps - 1

            print("Argument backtrace complete")

            if(constant):
                print("This wrmsr instance is a bad candidate. ECX is a constant. Discarding.")

            else: 
                print("This wrmsr is a good candidate. Recording in the database for further analysis.")

                wrmsr_db.append([filename,hex(ea)])


            print("######################")

print("Finished analysis")

print("Candiate wrmsr instructions for further analysis")

print(wrmsr_db)

print("Appending to CSV database")

for row in wrmsr_db:
    append_row(row)


            #Possibly useless


            #if insn.ops[0].type == ida_ua.o_mem:
            #    print("wrmsr takes a register value from memory at: %x" % insn.ops[1].value)
            #elif insn.ops[0].type == ida_ua.o_reg:
            #    print("wrmsr takes a register value from another register at: %x" % insn.ops[1].value)
            #elif insn.ops[0].type == ida_ua.o_mem:
            #    print("wrmsr takes a register value from a known memory address at: %x" % insn.ops[1].value)
            #elif insn.ops[0].type == ida_ua.o_phrase:
            #    print("wrmsr takes a register value from a pointer to an address: %x" % insn.ops[1].value)
            #elif insn.ops[0].type == ida_ua.o_displ:
            #    print("wrmsr takes a register value from a pointer to an address: %x" % insn.ops[1].value)
            #elif insn.ops[0].type == ida_ua.o_imm:
            #    print("wrmsr takes a register value from a constant (likely not useful!): %x" % insn.ops[1].value)


         #Check to see the operand type for
            #if insn.ops[1].type == ida_ua.o_mem:
            #    print("wrmsr takes a data value from memory at: %x" % insn.ops[1].value)
            #elif insn.ops[1].type == ida_ua.o_reg:
            #    print("wrmsr takes a data value from another register at: %x" % insn.ops[1].value)
            #elif insn.ops[1].type == ida_ua.o_mem:
            #    print("wrmsr takes a data value from a known memory address at: %x" % insn.ops[1].value)
            #elif insn.ops[1].type == ida_ua.o_phrase:
            #    print("wrmsr takes a data value from a pointer to an address: %x" % insn.ops[1].value)
            #elif insn.ops[1].type == ida_ua.o_displ:
            #    print("wrmsr takes a data value from a pointer to an address: %x" % insn.ops[1].value)
            #elif insn.ops[1].type == ida_ua.o_imm:
            #    print("wrmsr takes a data value from a constant (likely not useful!): %x" % insn.ops[1].value)
