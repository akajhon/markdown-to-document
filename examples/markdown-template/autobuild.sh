FILE="template.md"
PDF="template.pdf"

md5_old=$(md5sum $FILE | awk ' { print $1 }')

while true;
do
	sleep 5
	md5_new=$(md5sum $FILE | awk ' { print $1 }')
	if [[ $md5_old != $md5_new ]]; then
		echo -ne "\nTime: $(date +"%d/%m/%Y %H:%M:%S") - File change ✅"
		pandoc $FILE -o $PDF --from markdown --template eisvogel --pdf-engine xelatex
		md5_old="$md5_new"
	else
		echo -ne "\nTime: $(date +"%d/%m/%Y %H:%M:%S") - Not find any change ❌"
	fi
done
