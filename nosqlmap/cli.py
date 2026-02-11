#!/usr/bin/env python3
from nosqlmap.nosqlmap import build_parser, main

def cli():
    parser = build_parser()
    args = parser.parse_args()
    main(args)
