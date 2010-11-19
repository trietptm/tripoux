# Tripoux project - Joan Calvet - j04n.calvet@gmail.com
# Version : v0.1
# 
# This is a IDA python dummy script to delete the Tripoux comments and the colors


colorSwitch = AskYN(1,"Do you also want to delete ALL colors ?")

for seg_ea in Segments():
		for ea in range(seg_ea,SegEnd(seg_ea)):
			# Delete comments
			comment = GetCommentEx(ea,0)
			if(comment != None):
				if (comment.find("/T\\")!= -1):
					MakeComm(ea,"")
					
			# Delete colors
			if(colorSwitch):
				if(GetColor(ea,CIC_ITEM) != 0xFFFFFF):
					SetColor(ea,CIC_ITEM,0xFFFFFF)
			