import sys
import os
import datetime
import requests
import bz2


BASE_URL="http://archive.routeviews.org/oix-route-views"

def downloadBZ2(tar_dir, filename, url):
    #if not exist
    if not os.path.exists(tar_dir):
        os.mkdir(tar_dir)

    tar_file = tar_dir + '/'+filename
    if (os.path.isfile(tar_file)):
        print("file: "+filename+" already exists")
        return 0
    try:
        bz2file = requests.get(url)
        if (bz2file.status_code != 200):
            return 1
        print("begin to download file: " + filename)
        with bz2.BZ2File(tar_file,'wb') as f:
            f.write(bz2file.content)
        return 0
    except requests.exceptions.HTTPError as e:
        print("     !! HTTP Error while retrieving file: " + filename + ': ' + str(e.reason))
        return 1
    except Exception as excp:
        print("     !! Download failed:" + str(excp))
        return 1

args = len(sys.argv)
cur_date = datetime.date.today()
format_mon = '%Y.%m'
format = '%Y-%m-%d'

if (args < 2):
    print("Usage: bgp-scraper.py startdate=today targetDir")
elif (args < 3):
    print("No specified startdate, start from today:" + cur_date.strftime(format))
    start_date=cur_date
    res_dir = sys.argv[1]
else:
    try:
        start_date = datetime.datetime.strptime(sys.argv[1],format).date()
        res_dir = sys.argv[2]
    except:
        print("invalid format: "+format)
        sys.exit(1)

#list all months from start_date to cur_date
dates = []
date = start_date
end_date = start_date
while (date <= end_date):
    dates.append(date)
    date = date + datetime.timedelta(days=1)
    #print(date.strftime(format))

#print(dates)

for date in dates:
    tslist = [str(n).zfill(2) for n in range(0,24,2)]
    for ts in tslist:
        filename = 'oix-full-snapshot-' + date.strftime(format) + '-'+ts+'00.bz2'
        url = BASE_URL+'/'+date.strftime(format_mon)+'/'+filename
        tar_dir = res_dir+'/'+date.strftime(format)
        res = downloadBZ2(tar_dir,filename,url)