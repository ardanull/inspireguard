install:
	pip install -r requirements.txt

run:
	uvicorn app.main:app --reload

test:
	pytest -q

seed:
	python scripts/seed_demo.py

pcap:
	python scripts/analyze_pcap.py --pcap samples/demo.pcap
