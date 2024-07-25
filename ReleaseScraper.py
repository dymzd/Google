import requests
from lxml import html
import json
import shelve
import time

# Constants
URL = "https://support.google.com/chrome/a/answer/7679408?hl=ja"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"
MAIN_CONTENT_XPATH = '//div[@class="cc"]//td/a/text()'
RELEASE_NUMBER_XPATH = '//div[@class="cc"]/h2/text()'
BROWSER_OS_CONSOLE_XPATH = '//div[@class="cc"]/div/h2/text()'
FEATURE_TITLE_XPATH = '//div[@class="cc"]/div/ul/li/strong/text()'
FEATURE_DETAILS_XPATH = '//div[@class="cc"]/div/ul/li/p/text()'

STORAGE_FILE = "page_content.db"
CHECK_INTERVAL = 24 * 60 * 60  # 24 hours in seconds

def fetch_page_content():
    session = requests.Session()
    response = session.get(URL)
    response.raise_for_status()
    content = response.content.decode('utf-8')
    tree = html.fromstring(content)

    main_content = tree.xpath(MAIN_CONTENT_XPATH)
    release_number = tree.xpath(RELEASE_NUMBER_XPATH)[0].replace('の概要','')
    feature_elements = tree.xpath('//div[@class="cc"]/div/ul/li')

    link_to_content = tree.xpath('//tbody/tr/td/a/@href')

    features = []
    count = 0
    for feature in feature_elements:
        title = feature.xpath('.//strong/text()')[0] if feature.xpath('.//strong/text()') else "No title"
        details = []
        detail_elements = feature.xpath('.//p')
        browser_os_console = feature.xpath('preceding::h2[1]/text()')
        browser_os_console = browser_os_console[0] if browser_os_console else "Unknown Section"


        for detail in detail_elements:
            text_parts = []
            # Start with node's own text before the first child if available
            if detail.text:
                text_parts.append(detail.text.strip())

            # Iterate through child nodes and tails
            for node in detail.iterchildren():
                if node.tag == 'a':
                    # Try to find <u> tag within <a> tag
                    u_tag = node.find('.//u')
                    if u_tag is not None and u_tag.text is not None:
                        link_text = u_tag.text.strip()  # Use text from <u> tag if available
                    else:
                        # Default to node text or "Link" if no text is available
                        link_text = node.text.strip() if node.text else "Link"

                    link_url = node.get('href', 'No URL')

                    if "https://chromeenterprise.google/policies/#" in link_url:
                        link_text = link_url.strip('https://chromeenterprise.google/policies/#')
                    elif "https://chromeenterprise.google/policies/#" in link_text:
                        link_url = link_text.strip('https://chromeenterprise.google/policies/#')
                    if link_url != '#top':
                        text_parts.append(f"<{link_url}|{link_text}>")

                elif node.tag == 'strong':
                    bold_text = node.text.strip() if node.text else ""
                    if bold_text != "":
                        text_parts.append(f"*{bold_text}*")  # Markdown syntax for bold
                elif node.tag == 'em':
                    italic_text = node.text.strip() if node.text else ""
                    if italic_text != "":
                        text_parts.append(f"_{italic_text}_")  # Markdown syntax for italic
                elif node.tag == 'code':
                    code_text = node.text.strip() if node.text else ""
                    if code_text != "":
                        text_parts.append(f"`{code_text}`")  # Markdown syntax for code


                if node.tail:
                    text_parts.append(node.tail.strip())

            # Combine all parts into one string for this detail element
            full_detail = ' '.join(text_parts).strip()
            details.append(full_detail)

        features.append({'title': title, 'details': details,'releaseNum':release_number, 'whichSec':browser_os_console, 'url': link_to_content[count]})
        count = count + 1 
    content = {
        "Main Content": "\n".join(main_content),
        "Release Number": "\n".join(release_number),
        "Browser OS Console": "\n".join(browser_os_console),
        "Features": features
    }
    return content



def send_to_slack(features):
    for feature in features:
        # message = f"Feature: {feature['title']}\nDetails:\n" + "\n".join(feature['details'])
        slack_message = '\n'.join(feature['details'])
        # print(message)
        print(slack_message)
        print(f'https://support.google.com{feature["url"]}')
        if feature['details'] != []:
            slack_message = {
                "blocks": [
                    {
                        "type": "divider"
                    },
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{feature['title']}",
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{feature['whichSec']} : {feature['releaseNum']}"
                        },
                        "accessory": {
                            "type": "button",
                            "text": {
                                "type": "plain_text",
                                "text": "Releaase Note はこちら",
                                "emoji": True
                            },
                            "value": "Releaase Note はこちら",
                            "url": f"https://support.google.com{feature['url']}",
                            "action_id": "button-action"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{slack_message}",
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "いいね",
                                    "emoji": True
                                },
                                "value": "click_me_123"
                            }
                        ]
                    },
                    {
                        "type": "divider"
                    }
                ]
            }
            response = requests.post(SLACK_WEBHOOK_URL, data=json.dumps(slack_message), headers={'Content-Type': 'application/json; charset=utf-8'})
            response.raise_for_status()
            print("Feature message sent to Slack successfully.")

def check_for_updates():
    current_content = fetch_page_content()
    
    with shelve.open(STORAGE_FILE) as db:
        last_content = db.get("last_content", {})
        
        if current_content["Features"] != last_content.get("Features", []):
            send_to_slack(current_content["Features"])
            db["last_content"] = current_content
        else:
            print("No changes detected.")

def main():
    while True:
        check_for_updates()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
