#filename=my_scan
import yara
import os
import magic
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


RULES_FOLDER='/home/cipher/experiments/yara_rules/rules/cve_rules'
EXTRACTED_FOLDER='/home/cipher/experiments/SMT_X12AST2600_ROT_001080p/_SMT_X12AST2600_ROT_001080p.bin.extracted'


abs_yararule_pathes=list()
abs_fileToBeTest_pathes=list()
sources_dictionary=dict()


#===================================================================================================
#functionName: getYaraRules
#Description: create a list of absolute path of yara rules.
#===================================================================================================
def getYaraRules(rules_folder=RULES_FOLDER):
	for root, subdirectories, files in os.walk(rules_folder):
		for tfile in files:
			abs_filepath=os.path.join(root, tfile)
			abs_yararule_pathes.append(abs_filepath)
			logger.info(abs_filepaths)
			sources_dictionary[tfile]=abs_filepath


#==================================================================================================
#functionName: getFilesToBeTest
#Description: create a list of absolute path of files that need to be tested, which sould only be 
#	ELF file and exclued the symbol link in advance.
#==================================================================================================
def getFilesToBeTest(extracted_folder='/home/cipher/experiments/SMT_X12AST2600_ROT_001080p/_SMT_X12AST2600_ROT_001080p.bin.extracted'):
	for root, subdirectories, files in os.walk(extracted_folder):
		for tfile in files:
			if os.path.islink(tfile) or not os.path.exists(tfile):
				continue
			abs_filepath=os.path.join(root, tfile)
			if ELFFilter(abs_filepath):
				abs_fileToBeTest_pathes.append(abs_filepath)
				print('True')
			else:
				print('False')
			logger.info(abs_filepath)


#================================================================================================
#functionName: ELFFilter
#
#================================================================================================
def ELFFilter(filename):
	headString=''
	m=magic.from_file(filename)
	logger.info(m)
	try:
		headString=m.split(',')[0].split(r' ')[0]
	except ValueError:
		pass
	if headString=='ELF':
		return True
	else:
		return False


#===============================================================================================
#functionName: 	Scan
#
#===============================================================================================
def Scan(pathList=abs_fileToBeTest_pathes):
#	print(RULES_FOLDER)
	rules= yara.compile(sources=sources_dictionary)
	for ELFfile in pathList:
		matches=rules.match(ELFfile)
		print(matches)

#==============================================================================================
#functionName: 
#Description: 	program entry
#==============================================================================================
if __name__=='__main__':
	getFilesToBeTest()
	Scan()

