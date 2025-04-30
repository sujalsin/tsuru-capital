# Parse Quote - Tsuru Capital Application

This project is a specialized packet analyzer designed for processing and parsing financial market data from PCAP files. It specifically handles B6034 format quotes, which contain important market data including bid-ask spreads, quantities, and timestamps.

## Project Overview

The application processes network capture (PCAP) files containing financial market data and extracts structured information from B6034 format quotes. For each quote, it extracts:

- Quote acceptance timestamp
- ISIN (International Securities Identification Number)
- Bid orders (5 levels deep)
- Ask orders (5 levels deep)

Each bid and ask entry contains:
- Quantity
- Price

## Features

- Processes PCAP files containing UDP packets on ports 15515 and 15516
- Parses B6034 format quotes
- Supports chronological reordering of quotes (optional)
- Handles nanosecond-precision timestamps
- Outputs formatted quote data with timestamps

## Building and Running

The project uses a Makefile for easy building and cleaning:

### Build the project
```bash
make
```
This will compile the project in release mode and copy the executable to the current directory.

### Clean build artifacts
```bash
make clean
```

### Running the application
```bash
./parse-quote [-r] <file.pcap>
```

Options:
- `-r`: Enable chronological reordering of quotes (optional)
- `<file.pcap>`: Path to the PCAP file to analyze

## Output Format

The output is formatted as space-separated values:
```
timestamp ISIN bid5@price5 bid4@price4 bid3@price3 bid2@price2 bid1@price1 ask1@price1 ask2@price2 ask3@price3 ask4@price4 ask5@price5
```

Where:
- `timestamp`: Packet capture time
- `ISIN`: The security identifier
- `bidN@priceN`: Bid quantity and price at level N
- `askN@priceN`: Ask quantity and price at level N

## Example Output

Here's an example of the output when processing a PCAP file:

```
1297814400.006437 08595997 KR4201F32705 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000
1297814400.026326 08595999 KR4201F32804 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000
1297814400.031172 08595999 KR4301F32471 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000 0000000@00000
1297814400.500708 09000000 KR4301F32778 0000000@01340 0000000@01345 0000000@01350 0000000@01355 0000007@01360 0000003@01450 0000000@01455 0000000@01460 0000000@01465 0000000@01470
1297814400.501675 09000000 KR4301F42629 0000000@00505 0000000@00510 0000000@00515 0000032@00520 0000024@00525 0000001@00630 0000000@00635 0000000@00640 0000000@00645 0000000@00650
```

In this example:
- The first line shows a quote for ISIN `KR4201F32705` with no active orders (all quantities are 0)
- The fourth line shows a quote for ISIN `KR4301F32778` with:
  - A bid of 7 units at price 1360
  - An ask of 3 units at price 1450
- The fifth line shows a quote for ISIN `KR4301F42629` with:
  - Bids of 32 units at 520 and 24 units at 525
  - An ask of 1 unit at 630 