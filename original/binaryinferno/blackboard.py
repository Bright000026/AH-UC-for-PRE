# This file is part of BinaryInferno, a tool for binary protocol reverse engineering.
# Copyright (C) 2023 Jared Chandler (jared.chandler@tufts.edu)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>
#
# QC v.0.1 4/30/2023
#
# =======================================================================================
# __________.__                            .___        _____                           
# \______   \__| ____ _____ _______ ___.__.|   | _____/ ____\___________  ____   ____  
#  |    |  _/  |/    \\__  \\_  __ <   |  ||   |/    \   __\/ __ \_  __ \/    \ /  _ \ 
#  |    |   \  |   |  \/ __ \|  | \/\___  ||   |   |  \  | \  ___/|  | \/   |  (  <_> )
#  |______  /__|___|  (____  /__|   / ____||___|___|  /__|  \___  >__|  |___|  /\____/ 
#         \/        \/     \/       \/              \/          \/           \/        
# ---------------------------------------------------------------------------------------

from Sigma import ascii2sigma,bytes2ascii,intmsgs,hexmsgs,msgs,unknownify,SIGMA,FIELD,INTERVAL,UNIFY,mapUNIFY,allornone,getunknownfields,applyfield
import csv
import os



from lv import inferlength
from lv4 import inferlength4BE,inferlength4LE
from lv3 import inferlength3BE,inferlength3LE
from lv2 import inferlength2BE,inferlength2LE
from csum import inferchecksum
from ip import inferip
from set_seq_infer import inferidLE, inferidBE


from sequence import inferseq8BE,inferseq16BE,inferseq24BE,inferseq32BE
from sequence import inferseq8LE,inferseq16LE,inferseq24LE,inferseq32LE


from EdgeCases import inferconst32

import re


from float import inferfloatLE, inferfloatBE
from lvstar import inferlvstar
from lvone import inferlvone
from entropybound import inferentropyboundLE,inferentropyboundBE
from constant import inferconstant
from heading import inferheading
#from timestamp32 import inferts32
from timestamp64beta import infertsbe64,infertsle64,infertsle32,infertsbe32
from tsbyrange import mk_ts_functions                                           # Done
from nmibound import infernmibound                                              # Done
from rep_interface import rep_par, rep_par_BE, rep_par_LE



def allsamelength(xs):
  return len(set([len(x) for x in xs])) == 1
def onejob(foo):
  foo = patchinput(foo)





  #("nmi",infernmibound),("floatLE",inferfloatLE) #("checksum",inferchecksum),
  ensemble = [("boundBE",inferentropyboundBE),
              ("boundLE",inferentropyboundLE)] #,("rep_par",rep_par) ] #,("nmi",infernmibound),("bound",inferentropybound)]#,("heading",inferheading)]

  ensemble+=[ ("floatLE",inferfloatLE),
              ("floatBE",inferfloatBE)]
               #("ts64BE",infertsbe64),("ts64LE",infertsle64),
               #("ts32LE",infertsle32),("ts32BE",infertsbe32)] #("constant",inferconstant),("checksum",inferchecksum),
  if TSPAN != None:
    print("Time Span for TS Inference is",TSPAN)
    low_str,high_str = TSPAN
    fs = mk_ts_functions(low_str,high_str)
    ensemble+=fs
  ensemble+=[("seq8LE",inferseq8LE),("seq16LE",inferseq16LE),("seq24LE",inferseq24LE),("seq32LE",inferseq32LE)]
  ensemble+=[("seq8BE",inferseq8BE),("seq16BE",inferseq16BE),("seq24BE",inferseq24BE),("seq32BE",inferseq32BE)]
  #ensemble+=[("checksum",inferchecksum)] #,("constant32",inferconst32)]
  
  #ensemble+=[("set_seq_LE",inferidLE) , ("set_seq_BE",inferidBE)]
  #if not allsamelength(txtmsgs) :
  ensemble+=[#("rep",text2repsigmas),
            ("length",inferlength),
            ("length2LE",inferlength2LE),
            ("length2BE",inferlength2BE),
            ("length3LE",inferlength3LE),
            ("length3BE",inferlength3BE),
            ("length4LE",inferlength4LE),
            ("length4BE",inferlength4BE),
            ("rep_par_BE",rep_par_BE),
            ("rep_par_LE",rep_par_LE)
              ] #,("lvstar",inferlvstar),("lvone",inferlvone)]


  # if len(sys.argv) > 1:
  #   filtered_ensemble = [e for e in ensemble if e[0] == sys.argv[1]]
  #   if len(filtered_ensemble) ==0:
  #     print("Unknown ensemble member: ",sys.argv[1])
  #     print("")
  #     sys.exit()
  #   ensemble = filtered_ensemble
  if args.detectors != []:
    if args.detectors == ['LE']:
      print("filtering detectors to LE detectors")
      filtered_ensemble = [e for e in ensemble if e[0][-2:] != 'BE']
    elif args.detectors == ['BE']:
      print("filtering detectors to BE detectors")
      filtered_ensemble = [e for e in ensemble if e[0][-2:] != 'LE']
    else:
      filtered_ensemble = [e for e in ensemble if e[0] in args.detectors]
      if len(filtered_ensemble) != len(args.detectors):
        print("Problem limiting to detectors you specified",args.detectors)
        #sys.exit()
    ensemble = filtered_ensemble
  print("-"*40)
  print("Using the following Detectors:")
  #for e in ensemble:
  #  print(e[0],e[0][-2:],e[0][-2:] in args.detectors,args.detectors)
  print("-"*40)
  print("")


  from Booster import booster
  sigmas = []
  results = booster(ensemble,foo)
  for l,f,xres in results:
    if type(xres) == type([]):
      pass
    else:
      xres = [xres]
    if "rep_par" not in l:
      #print("Make all fields in these sigmas disjoint")
      new_sigmas = []
      for res in xres:
        for f in res.fields:
          new_sigmas.append(SIGMA([f]))

      xres = new_sigmas
      #print("final xres",xres)
    for res in xres:
      if res.fields == []:
        print("\tDidn't find anything")
      else:

        #print("\tFound Sigma:",res)

        # What does this do? 
        
        #res = allornone(res,foo)
        pass
        #print("\tFound Sigma:",res)
        #print("\t" + "-"*70)
        try:
          #print(indent(res.apply(foo)))
          sigmas.append(res)
        except:
          pass
        #print("."*80)
  for s in sigmas:
    print("sigma",s)
  #quit()


  if False:
    sigmas = []
    for l,f in ensemble: #("lvone",inferlvone), #,("ip",inferip)]:
      print("="*80)
      print("Searching for",l)

      print("-"*80)

      # Result of running the dector
      xres = f(foo)
      #print(l,"xres",xres)
      if type(xres) == type([]):
        pass
      else:
        xres = [xres]
      if "rep_par" not in l:
        #print("Make all fields in these sigmas disjoint")
        new_sigmas = []
        for res in xres:
          for f in res.fields:
            new_sigmas.append(SIGMA([f]))

        xres = new_sigmas
        #print("final xres",xres)
      for res in xres:
        if res.fields == []:
          print("\tDidn't find anything")
        else:


          res = allornone(res,foo)
          print("\tFound Sigma:",res)
          print("\t" + "-"*70)

          print(indent(res.apply(foo)))
          sigmas.append(res)
          #print("."*80)



    def sigmas2indexes(sigmas):
      from collections import Counter
      res = []
      for s in sigmas:
        for f in s.fields:
          for interval in f.intervals:
            res.append(interval.start)
            res.append(interval.stop)

      return Counter(res)

  print("")
  print("="*80)
  print("UNIFYING SIGMAS")
  print("-"*80)

  def countBELE(sigmas):
    BE = 0
    LE = 0
    for s in sigmas:
      for f in s.fields:
        print("f.anno",f.annotation)
        if "BE " == f.annotation[:3]:
          BE+=1
          print("be BE")
        elif "LE " in f.annotation[:3]:
          LE+=1
          print("le LE")
        elif  "big" in f.annotation:
          if "2" in f.annotation or "3" in f.annotation or "4" in f.annotation:
            BE+=1
            print("be big")
        elif "little" in f.annotation:
          if "2" in f.annotation or "3" in f.annotation or "4" in f.annotation:
            LE+=1
            print("le little")
        else:
          pass
    return (BE,LE)

  def predictBELE(BE,LE):
    if BE == LE:
      return "NA"
    if BE > LE:
      return "BE"
    if LE > BE:
      return "LE"

    return "ERR"

  preBE,preLE=countBELE(sigmas)
  # If not all same
  # Then we need to break down and make choices regarding Length and xsums
  if not allsamelength(txtmsgs):
    length_sigmas = []
    nonlength_sigmas =[]
    for i,sigma in enumerate(sigmas):
      if sigma != SIGMA([]):
        if "L" in [f.ty() for f in sigma.fields ]:
          length_sigmas.append(sigma)
        else:
          nonlength_sigmas.append(sigma)


    # Choose the best length field
    # We choose things which correspond strictly to length over fuzzy matches.
    # We choose the earliest field possible. 
    
    def ranklengthfields(sigmas):
      # Given empty sigmas, return a single empty 
      if len(sigmas) ==0:
        return SIGMA([])

      fuzzy_len_fields =[]
      nonfuzzy_len_fields = []

      # Divide all fields out as fuzzy or non fuzzy
      for s in sigmas:
        for f in s.fields:
          if "Fuzzy" in f.annotation and f.ty()=="L":
            fuzzy_len_fields.append(f)
          else:
            nonfuzzy_len_fields.append(f)

      # Prefer nonfuzzy lens, choose earliest, largest
      if len(nonfuzzy_len_fields) > 0:
        len_fields = sorted(nonfuzzy_len_fields)[::-1]
      else:
        len_fields = sorted(fuzzy_len_fields)[::-1]

      for f in len_fields:
        print("len_field",f)

      # Get the starting offsets from the intervals of the first field

      len_fields = sorted(len_fields,key=lambda x: x.intervals[0].start)

      starts = [i.start for i in len_fields[0].intervals]
      
      # Get all fields which have the same "earliest start"
      fields = [f for f in len_fields if [i.start for i in f.intervals] == starts]

      # Get the field from those with the largest width
      sorted_fields = sorted(fields,key=lambda x: -x.width)
      for s in sorted_fields:
        print("sorted",s)
      best_length_field = sorted_fields[0]
      #return SIGMA(sorted_fields)
      return SIGMA([best_length_field])

    # sz = SIGMA([FIELD([INTERVAL("z",4,5) for i in range(4)])])
    # nonlength_sigmas+=[sz]

    if True:
      ranklengthfields(length_sigmas)
      for s in nonlength_sigmas:
        print("NonLength Sigma",s)

      print("")
      for s in length_sigmas:
        print("Length Sigma",s,[f.annotation for f in s.fields])

    print("")
    length_sigma = ranklengthfields(length_sigmas)
    print("Best Length Sigma",length_sigma)

    print("")

    # Filter out anything which intersects with a length field
    filtered_sigmas = []
    for s in nonlength_sigmas:
      #print("Filter",length_sigma,s)
      valid = True
      for f1 in length_sigma.fields:
        # If all the fields in s don't intersect with f1, 

        # if any field in the length figma intersects with something in s
        # bail

        if any([f1.intersect(f2) for f2 in s.fields]):
          valid = False


      if valid:
        filtered_sigmas.append(s)

      print("Do",s,"and",length_sigma,"intersect?", not valid)
         

      # print("\t","f1",f1,"f2",f2,"f1^f2",f1 ^ f2,f2^f1,f1<=f2,f1.intersect(f2))
      # for i,i1 in enumerate(f1.intervals):
      #   i2 = f2.intervals[i]
      #   print("\t\t",i1,i2,i1^i2,i1==i2,i1.intersect(i2)) 

         
    print("")
    sigmas = filtered_sigmas + [length_sigma]

  for i,v in enumerate(sigmas):
    print("\ts"+str(i),":",v,[f.value for f in v.fields],[f.annotation for f in v.fields])

  #print(sigmas2indexes(sigmas))


  if True:
    print("\tu"+"-"*70)
    if sigmas != []:
      s = mapUNIFY(sigmas)
      print("TotalValue",s.value)
    else:
      s = SIGMA([])
    print("s!!!!!!!", s)
    print(len(txtmsgs))
    msgs_num = len(txtmsgs)
    format_res = [[0] for _ in range(msgs_num)]
    for fields in s.fields:
      print(fields)
      print([intervals for intervals in fields.intervals])
      msgs_intervals = [intervals for intervals in fields.intervals]
      if len(msgs_intervals) > len(format_res):
        msgs_intervals = msgs_intervals[:len(format_res)]
      for index, interval in enumerate(msgs_intervals):
        format_res[index].append(interval.start)
        format_res[index].append(interval.stop)
    final_format = []
    for format in format_res:
      #print(list(set(format)))
      final_format.append(sorted(list(set(format))))
   
    """
    BE,LE=countBELE([s])
    print("PREDICTENDIAN","preBE",preBE,"preLE",preLE,"BE",BE,"LE",LE,"PREDICTPRE",predictBELE(preBE,preLE),"PREDICTFINAL",predictBELE(BE,LE),"TV",s.value)


    print("\ts ",":",s)
    print("")
    print("="*80)
    print("INFERRED DESCRIPTION")
    print("-"*80)



    print("")
    #print(indent(s.apply(foo)))
    print("")
    print("QTY SAMPLES")
    
    print(len(msgs(foo)))
    print("HEADER ONLY")
    try:
      v =s.apply(foo).split("\n")[0]
      print(v)
    except:
      print("Problem generating header only")
    # if len(sys.argv) > 2:
    #   goal = sys.argv[2]  
    #   print(s,str(s)==goal)

    def field2spec(f,loc):

      def cleanup_repeated_fields(annotation):
        annotation = annotation.upper()
        if annotation[-1] == "*":
          annotation = "*Q_" + annotation[:-1]
        annotation = annotation.replace("_V","_1V")
        annotation = annotation.replace("FW","_")
        annotation = annotation.replace("_BIG","_BE")

        annotation = annotation.replace("_LITTLE","_LE")
        return annotation.upper()

      def extractendian(annotation):
        endian = ""
        if "BE " in annotation or "_big" in annotation or  "_BIG" in annotation:
          endian = "_BE"

        if "LE"  in annotation or "_little" in annotation or "_LITTLE" in annotation:
          endian = "_LE"
        return endian

      # For zero width intervals, we ignore since they've been used for splits
      endian = extractendian(f.annotation)
      if f.ty() == "|":
        return []

      # If it's not an R (variable length portion)
      if f.ty() != "R":
        if f.ty() == "L":
          return ["Length "+f.str_width()+"V"+endian+ " (" + f.annotation+ ")"]
        else:
          #pass
          #return ["Field "+f.str_width()+"V"+endian]
          if "Variable Length" in f.annotation:
            return ["FieldVar "+"*V"+endian+ " (" + f.annotation+ ")"]
          else:
            return ["FieldFixed "+f.str_width()+"V"+endian+ " (" + f.annotation+ ")"]
      else:
        return ["FieldRep " +cleanup_repeated_fields(f.annotation)+ " (" + f.annotation+ ")"]
    #print("Final Sigma",unknownify(s,foo))
    specres = []
    for f in unknownify(s,foo).fields:
      specres+=field2spec(f,0)
      #print("\t",f,f.ty(),f.width,f.annotation,)
    print("SPECSTART")
    print("\n".join(specres))
    print("SPECEND")

    # If we are doing recursive inference on the unknown regions...
    if args.recurse:
      print("="*80)
      print("UNKNOWN REGIONS TO RECURSE ONTO")
      print("-"*80)

      def updatestarts(fold,fnew):
        for i,v in enumerate(fold.intervals):
          fnew.intervals[i].shift(v.start)
        return fnew

      unk = getunknownfields(s,foo)
      for u in unk:
        fold = u.fields[0]
        print(fold.startallsame(),u)
        if args.recurse and not fold.startallsame():
          print("\tRecusing on",u)
          recurse_data = "\n".join([v.hex() for v in applyfield(fold,foo)])
          print(recurse_data)
          rv = onejob(recurse_data)
          print("==>",rv)
          rv = SIGMA([updatestarts(fold,fnew) for fnew in rv.fields])
          print("==>",rv)
          # So we got something
          s2 = mapUNIFY([s,rv])
          print(s2)
          print("")
          print(indent(s2.apply(foo)))
          print("")


    # Dump the string rep of the inferred description
    if args.sigmaonly:
      print("="*80)
      print("SIGMA ONLY")
      print("-"*80)
      print(str(s))
    """
    return final_format
    return s

# Do the inference


if __name__ == "__main__":

  import argparse

  parser = argparse.ArgumentParser(description='Process some integers.')
  # parser.add_argument('integers', metavar='N', type=int, nargs='+',
  #                     help='an integer for the accumulator')
  parser.add_argument('--filename', dest='filename', default=None, help='Filename to Read Input From')
  parser.add_argument('--detectors', dest='detectors', nargs='+', default=[], help='use only a single specific detector')
  parser.add_argument('--sigmaonly', dest='sigmaonly', action='store_const',const=True,default=False, help='Report Only the Final Inferred description')
  parser.add_argument('--recurse', dest='recurse', action='store_const',const=True, default=False, help='Attempt Recursive Inference on Unknown portions')
  parser.add_argument('--n', dest='maxmsgs', default=None, type=int, help='Maximum Number of Messages to Use for Inference')
  parser.add_argument('--tslow', dest='tslow', default=None,  help='Datetime Range Low')
  parser.add_argument('--tshigh', dest='tshigh', default=None,  help='Datetime Range High')
  parser.add_argument('--clustering', dest='clustering', default=1,  help='whether use clustering')
  parser.add_argument('--header', dest='header', default=None,  help='whether to seperate header, defaule is None')
  

  #2021-05-05 00:00:00.000000
  #parser.add_argument('--sigmaonly', dest='detector', default=None, help='use only a specific detector')
  args = parser.parse_args()
  print("args",args)
  #args.recurse = True
  print("clustering!!", args.clustering)
  if args.tslow != None and args.tshigh != None and args.tslow != "" and args.tshigh != "":
    TSPAN = (re.sub("'","",args.tslow) + ".000000",re.sub("'","",args.tshigh)+".000000")
  else:
    TSPAN = None

  #args.detectors = ["rep_par","boundLE"]

  from rep_harness import text2repsigmas

  def indent(txt):
    return "\n".join(["\t"+x for x in txt.split("\n")])


  # Limit messages used to nb
  def limit(txt,n):
    xs = txt.split("--")

    vs = xs[1].strip().split("\n")[:n]


    xs[1] = "\n"+"\n".join(vs)+"\n"
    new_xs  = "--".join(xs)
    return new_xs

  import re
  def patchinput(txt):
    if "--" not in txt:
      v=  "?\n--\n" + txt.strip() + "\n--"
    else:
      v=  txt
    v = v.replace("\t","")
    v = v.replace(" ","")
    if args.maxmsgs != None:
      v = limit(v,args.maxmsgs)
    return v
  
  def calculate_metrics(pred_offsets, true_offsets, data_length):

    true_offsets = sorted(true_offsets)
    print(pred_offsets, true_offsets, type(pred_offsets))
   
    if data_length in pred_offsets:
        pred_offsets.remove(data_length)
    if data_length in true_offsets:
        true_offsets.remove(data_length)
    #many times the res extracted from wireshark is not that acccurate, especially miss the format information of payload
    #so we test to make some changes to correct the mismetrics
    pred_offsets = [x for x in pred_offsets if x <= true_offsets[-1]]
  
    pred_set = set(pred_offsets)
    true_set = set(true_offsets)


    TP = len(pred_set.intersection(true_set)) 
    FP = len(pred_set - true_set)            
    FN = len(true_set - pred_set)            

   
    all_possible_offsets = set(range(data_length))
    TN = len(all_possible_offsets - pred_set - true_set)

    
    ACC = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) != 0 else 0
    Precision = TP / (TP + FP) if (TP + FP) != 0 else 0
    Recall = TP / (TP + FN) if (TP + FN) != 0 else 0
    F1 = 2 * (Precision * Recall) / (Precision + Recall) if (Precision + Recall) != 0 else 0
    FPR = FP / (FP + TN) if (FP + TN) != 0 else 0
    
    perfection_count = 0
    pred_sorted = sorted(pred_set)  
    true_sorted = sorted(true_set)  

    
    true_index_dict = {value: idx for idx, value in enumerate(true_sorted)}

    for i in range(len(pred_sorted) - 1):
        a = pred_sorted[i]
        b = pred_sorted[i + 1]
        
        if a in true_index_dict and b in true_index_dict:
            if true_index_dict[b] == true_index_dict[a] + 1:
                perfection_count += 1

    
    perfection_ratio = perfection_count / (len(true_sorted) - 1) if len(true_sorted) > 1 else 0
    
    print(ACC, F1, Precision, Recall, FPR, perfection_ratio)
    return ACC, F1, Precision, Recall, FPR, perfection_ratio
  
  import csv
  import ast
  def evaluate_csv(csv_file_path, calculate_metrics):
     
      metric_columns = ['ACC', 'F1', 'Precision', 'Recall', 'FPR', 'Perfection']
      
      
      all_metrics = {metric: [] for metric in metric_columns}
      
     
      rows = []
      with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
          reader = csv.reader(csvfile)
          header = next(reader) 
          
          
          for column in metric_columns:
              if column not in header:
                  header.append(column)  
          rows.append(header)
          
        
          hex_index = header.index('Hex') if 'Hex' in header else -1
          segment_index = header.index('Segment') if 'Segment' in header else -1
          predict_segment_index = header.index('Predict_Segment') if 'Predict_Segment' in header else -1
          label_index = header.index('Predicted_Labels') if 'Predicted_Labels' in header else -1
          
          if hex_index == -1 or segment_index == -1 or predict_segment_index == -1:
              raise ValueError("CSV 文件中缺少 'Hex', 'Segment' 或 'Predict_Segment' 列")
          
         
          for row in reader:
              if row[label_index] == '-1':
                
                    rows.append(row)  
                    continue
             
              hex_value = row[hex_index]
              segment_value = ast.literal_eval(row[segment_index])
              predict_segment_value = ast.literal_eval(row[predict_segment_index])
              if segment_value == []:
                  rows.append(row)
                  continue
              
              
              metrics = calculate_metrics(predict_segment_value, segment_value, len(hex_value)//2)
                
              for i, column in enumerate(metric_columns):
                  if column in header:
                      index = header.index(column)
                      if index < len(row):
                          row[index] = metrics[i]  
                      else:
                          row.append(metrics[i]) 
                  else:
                      row.append(metrics[i])  
              
              
              for i, column in enumerate(metric_columns):
                  all_metrics[column].append(metrics[i])  
              
             
              rows.append(row)
      
    
      average_metrics = {column: sum(values) / len(values) for column, values in all_metrics.items()}
      
      
      with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
          writer = csv.writer(csvfile)
          writer.writerows(rows)
      
     
      return average_metrics
  

  
  def read_csv(csv_file_path, clustering, header):
    classified_data = {}
    classified_data_header = {}
    with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)  

        
        for row_index, row in enumerate(reader):
           
            hex_value = row['Hex']  
            predicted_label = row['Predicted_Labels']  
            
            if clustering == '0':
                if "Hex" not in classified_data:
                    classified_data["Hex"] = []
                classified_data["Hex"].append((hex_value, row_index))
           
            elif header != None:
                if "Hex" not in classified_data_header:
                    classified_data_header["Hex"] = []
                classified_data_header["Hex"].append((hex_value, row_index)) 
                
                if predicted_label not in classified_data:
                    classified_data[predicted_label] = []

               
                classified_data[predicted_label].append((hex_value, row_index))
                
            
            else:
                if predicted_label not in classified_data:
                    classified_data[predicted_label] = []

               
                classified_data[predicted_label].append((hex_value, row_index))

    if header == None:
        
        result = []
        labels = []
        for predicted_label, data in classified_data.items():
            result.append(data)  
            labels.append(predicted_label)  
        return result, labels
    else:
        result = []
        labels = []
        for predicted_label, data in classified_data.items():
            result.append(data)  
            labels.append(predicted_label)  
        result_header = []
        labels_header = []
        for predicted_label, data in classified_data_header.items():
            result_header.append(data) 
            labels_header.append(predicted_label) 
        return result, labels, result_header, labels_header
    
  def save_res_csv(csv_file_path, result_format):
      rows = []
      with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csvfile:
          reader = csv.reader(csvfile)
          header = next(reader) 

       
          if 'Predict_Segment' not in header:
              header.append('Predict_Segment') 
          rows.append(header)

         
          predict_segment_index = header.index('Predict_Segment') if 'Predict_Segment' in header else len(header) - 1

         
          for row_index, row in enumerate(reader):
              if row_index in result_format:
                  if len(row) > predict_segment_index:
                      row[predict_segment_index] = result_format[row_index]  
                  else:
                      row.append(result_format[row_index])  
              else:
                  if len(row) <= predict_segment_index:
                      row.append('')  
              rows.append(row)


      with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csvfile:
          writer = csv.writer(csvfile)
          writer.writerows(rows)


  import sys


  if args.filename != None:
    file_extension = os.path.splitext(args.filename)[1].lower()

    if file_extension == '.csv':
       
        if args.header == None:
            result, labels = read_csv(args.filename, args.clustering, args.header)
        else:
            result, labels, result_header, labels_header = read_csv(args.filename, args.clustering, args.header)
        result_format = {}
        result_format_header = {}
        
        
        #we use clustering 
        if args.clustering != '0' and args.header == None:
            for i, sublist in enumerate(result):
                print(f"List {i + 1} (Predicted_Labels = {labels[i]}):")
                if labels[i] == "-1":
                  continue
                
                hex_values = [item[0] for item in sublist] 
                input = '\n'.join(hex_values)  
                foo = patchinput(input)
                txtmsgs = msgs(foo.strip())
                format = onejob(foo)
                
                row_indices = [item[1] for item in sublist]
               
                for idx, result_value in zip(row_indices, format):
                    result_format[idx] = result_value
            print("format: ",format)
        elif args.clustering != '0' and args.header != None:
            header = int(args.header)+1
            sublist_header = result_header[0]  
            hex_values_header = [item[0] for item in sublist_header] 
            input_header = '\n'.join(hex_values_header)
            foo_header = patchinput(input_header)
            txtmsgs = msgs(foo_header.strip())
            format_header = onejob(foo_header)
            row_indices_header = [item[1] for item in sublist_header] 
            for idx, result_value in zip(row_indices_header, format_header):
                result_format_header[idx] = result_value
            
            for i, sublist in enumerate(result):
                print(f"List {i + 1} (Predicted_Labels = {labels[i]}):")
                if labels[i] == "-1":
                  continue

                hex_values = [item[0] for item in sublist] 
                input = '\n'.join(hex_values) 
                foo = patchinput(input)
                txtmsgs = msgs(foo.strip())
                format = onejob(foo)
                
                row_indices = [item[1] for item in sublist]
   
                for idx, result_value in zip(row_indices, format):
                    result_format[idx] = result_value
            
            
            #here we need to mix the two format
            row_indices_header = [item[1] for item in sublist_header]  
            for idx in row_indices_header:
                  #result_format_header = [x for x in result_format_header if x <= header]
                  
                  if idx not in result_format:
                      
                      result_format[idx] = result_format_header[idx]
                  else:
                      result_format[idx] = sorted([x for x in result_format_header[idx] if x <= header] + [x for x in result_format[idx] if x > header])
                  print(result_format[idx])
                  print(result_format_header[idx])
            #print("format: ",format)
            
        #we dont use clustering, test for original binaryinferno
        else:
            sublist = result[0]  
            hex_values = [item[0] for item in sublist]  
            input = '\n'.join(hex_values) 
            foo = patchinput(input)
            txtmsgs = msgs(foo.strip())
            format = onejob(foo)  


            row_indices = [item[1] for item in sublist]  
            for idx, result_value in zip(row_indices, format):
                result_format[idx] = result_value
            
            print("format: ",format)
        save_res_csv(args.filename, result_format)
        average_metrics = evaluate_csv(args.filename, calculate_metrics)
        print("average_metrics", average_metrics)
        

    else:
        f = open(args.filename)
        #print("f.read()",f.read())
        foo = patchinput(temp:=f.read())
        txtmsgs = msgs(foo.strip())
        format = onejob(foo)
        print("format: ",format)
        
        f.close()
  else:
    foo = patchinput("01000D60A67AED054150504C45\n01001160A67B0504504C554D0450454152\n01000E60A67AF9064F52414E4745")
    #foo =  patchinput(sys.stdin.read())

  #print("foo",foo)
if foo.strip() == "":
  print("Error: No input provided")
  quit()


banner=""" ___    ___ ___       ___  ________   ________ _______   ________     
|\  \  /  /|\  \     |\  \|\   ___  \|\  _____\\  ___ \ |\   __  \    
\ \  \/  / | \  \    \ \  \ \  \\ \  \ \  \__/\ \   __/|\ \  \|\  \   
 \ \    / / \ \  \    \ \  \ \  \\ \  \ \   __\\ \  \_|/_\ \   _  _\  
  /     \/   \ \  \____\ \  \ \  \\ \  \ \  \_| \ \  \_|\ \ \  \\  \| 
 /  /\   \    \ \_______\ \__\ \__\\ \__\ \__\   \ \_______\ \__\\ _\ 
/__/ /\ __\    \|_______|\|__|\|__| \|__|\|__|    \|_______|\|__|\|__|
|__|/ \|__|                                                           
"""

print(banner)
print("~"*80)
print("INPUT DATA")
short = "\n".join(foo.strip().split("\n")[:40])
print(indent(short))


txtmsgs = msgs(foo.strip())
print("args",args)
#onejob(foo)



