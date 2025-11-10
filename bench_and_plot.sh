#!/usr/bin/env bash
./build_libs.sh && make && ./secp-plugbench results.csv
uv run --with "pandas,seaborn" `pwd`/plot.py
uv run --with "pandas,seaborn" `pwd`/plot_line_log.py
