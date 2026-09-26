run:
	python app.py

install:
	pip install -r requirements.txt

compile:
	python -m py_compile app.py engine/detector.py engine/signatures.py engine/utils.py engine/pe_analyzer.py engine/reputation.py
