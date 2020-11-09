#!/usr/bin/env python3

import bitstring
import argparse
import sys
import json
import pretty_j1939.parse

pretty_j1939.parse.init_j1939db()

id_dict = {}
def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")


parser = argparse.ArgumentParser(description='pretty-printing J1939 candump logs')
parser.add_argument('candump', help='candump log')
parser.add_argument('--candata', type=str2bool, const=True, default=False, nargs='?',
                    help='print input can data')
parser.add_argument('--pgn',     type=str2bool, const=True, default=True, nargs='?',
                    help='print source/destination/type description')
parser.add_argument('--spn',     type=str2bool, const=True, default=True, nargs='?',
                    help='print signals description')
parser.add_argument('--transport', type=str2bool, const=True, default=True, nargs='?',
                    help='print details of transport-layer streams found')
parser.add_argument('--link', type=str2bool, const=True, default=True, nargs='?',
                    help='print details of link-layer frames found')
parser.add_argument('--include-na', type=str2bool, const=True, default=False, nargs='?',
                    help='inlude not-available (0xff) SPN values')
parser.add_argument('--format',  type=str2bool, const=True, default=False, nargs='?',
                    help='format each structure (otherwise single-line)')

args = parser.parse_args()

describer = pretty_j1939.parse.get_describer(describe_pgns=args.pgn, describe_spns=args.spn,
                                             describe_link_layer=args.link, describe_transport_layer=args.transport,
                                             include_transport_rawdata=args.candata,
                                             include_na=args.include_na)
if __name__ == '__main__':
    with open(args.candump, 'r') as f:
        for candump_line in f.readlines():
            if candump_line == '\n':
                continue
            try:
                #  (0000000029.695353)  can1  0CF00400   [8]  51 81 8A 44 14 00 F3 8A
                timestamp = float(candump_line.split(
                    ' ')[1].replace('(', '').replace(')', ''))
                message_id = bitstring.ConstBitArray(
                    hex=candump_line.split(' ')[5])
                message_data = bitstring.ConstBitArray(
                    hex=''.join(candump_line.split(' ')[10:]))
                # print(timestamp)
                # print(message_id)
                # print(message_data)
                if message_id in id_dict:
                    id_dict[message_id]+=1
                else:
                    id_dict[message_id] =1


            except IndexError:
                print("Warning: error in line '%s'" % candump_line, file=sys.stderr)
                continue
            except ValueError:
                print("Warning: error in line '%s'" % candump_line, file=sys.stderr)
                continue

            desc_line = ''

            description = describer(message_data.bytes, message_id.uint)
            key,val = description.popitem()
            print(type(key), " ", type(val))
            print(key, " ", val)