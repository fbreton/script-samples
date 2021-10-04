for i in $(lacework vulnerability container list-assessments --json | jq -r '.[] |select(any(.image_tags[]; . == "sidecar"))|.image_digest')
do
lacework vulnerability container show-assessment --json $i
done