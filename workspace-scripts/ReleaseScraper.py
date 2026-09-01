import json
import shelve
import sys
import time
from typing import Any, Dict, List

from lxml import html
import requests

# Constants
URL = "https://support.google.com/chrome/a/answer/7679408?hl=ja"
SLACK_WEBHOOK_URL = ""
MAIN_CONTENT_XPATH = '//div[@class="cc"]//td/a/text()'
RELEASE_NUMBER_XPATH = '//div[@class="cc"]/h2/text()'
STORAGE_FILE = "page_content.db"
CHECK_INTERVAL = 24 * 60 * 60  # 24 hours in seconds
REQUEST_TIMEOUT = 30


def clean_policy_url_or_text(text: str) -> str:
    """Safely strip the Chrome Enterprise policy URL prefix."""
    prefix = "https://chromeenterprise.google/policies/#"
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def fetch_page_content() -> Dict[str, Any]:
    session = requests.Session()
    response = session.get(URL, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    content = response.content.decode('utf-8')
    tree = html.fromstring(content)

    main_content_nodes = tree.xpath(MAIN_CONTENT_XPATH)
    main_content = [str(m).strip() for m in main_content_nodes if str(m).strip()]

    release_number_nodes = tree.xpath(RELEASE_NUMBER_XPATH)
    release_number = (
        str(release_number_nodes[0]).replace('の概要', '').strip()
        if release_number_nodes
        else "Unknown"
    )

    feature_elements = tree.xpath('//div[@class="cc"]/div/ul/li')
    link_to_content = tree.xpath('//tbody/tr/td/a/@href')

    features: List[Dict[str, Any]] = []
    for count, feature in enumerate(feature_elements):
        title_nodes = feature.xpath('.//strong/text()')
        title = str(title_nodes[0]).strip() if title_nodes else "No title"

        details: List[str] = []
        detail_elements = feature.xpath('.//p')
        browser_os_console_nodes = feature.xpath('preceding::h2[1]/text()')
        browser_os_console = (
            str(browser_os_console_nodes[0]).strip()
            if browser_os_console_nodes
            else "Unknown Section"
        )

        for detail in detail_elements:
            text_parts: List[str] = []
            if detail.text:
                text_parts.append(detail.text.strip())

            for node in detail.iterchildren():
                if node.tag == 'a':
                    u_tag = node.find('.//u')
                    if u_tag is not None and u_tag.text is not None:
                        link_text = u_tag.text.strip()
                    else:
                        link_text = node.text.strip() if node.text else "Link"

                    link_url = node.get('href', 'No URL')

                    link_text = clean_policy_url_or_text(link_text)
                    if link_url.startswith("https://chromeenterprise.google/policies/#"):
                        link_text = clean_policy_url_or_text(link_url)

                    if link_url != '#top':
                        text_parts.append(f"<{link_url}|{link_text}>")

                elif node.tag == 'strong':
                    bold_text = node.text.strip() if node.text else ""
                    if bold_text:
                        text_parts.append(f"*{bold_text}*")
                elif node.tag == 'em':
                    italic_text = node.text.strip() if node.text else ""
                    if italic_text:
                        text_parts.append(f"_{italic_text}_")
                elif node.tag == 'code':
                    code_text = node.text.strip() if node.text else ""
                    if code_text:
                        text_parts.append(f"`{code_text}`")

                if node.tail:
                    text_parts.append(node.tail.strip())

            full_detail = ' '.join(part for part in text_parts if part).strip()
            if full_detail:
                details.append(full_detail)

        feature_url = link_to_content[count] if count < len(link_to_content) else ""
        features.append({
            'title': title,
            'details': details,
            'releaseNum': release_number,
            'whichSec': browser_os_console,
            'url': feature_url,
        })

    return {
        "Main Content": "\n".join(main_content),
        "Release Number": release_number,
        "Browser OS Console": browser_os_console if 'browser_os_console' in locals() else "",
        "Features": features,
    }


def send_to_slack(features: List[Dict[str, Any]]) -> None:
    if not SLACK_WEBHOOK_URL:
        print("Notice: SLACK_WEBHOOK_URL is not set. Skipping Slack notification.")
        return

    for feature in features:
        if not feature['details']:
            continue

        slack_message_body = '\n'.join(feature['details'])
        release_num = feature['releaseNum']
        sec = feature['whichSec']
        if "今後の予定" in sec:
            release_num = ""

        feature_url = (
            f"https://support.google.com{feature['url']}"
            if feature['url'].startswith('/')
            else feature['url']
        )

        slack_payload = {
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
                        "text": f"{sec} : {release_num}".strip(" :")
                    },
                    "accessory": {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "Release Note はこちら",
                            "emoji": True
                        },
                        "value": "Release Note はこちら",
                        "url": feature_url or URL,
                        "action_id": "button-action"
                    }
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{slack_message_body}",
                    }
                },
                {
                    "type": "divider"
                }
            ]
        }
        try:
            response = requests.post(
                SLACK_WEBHOOK_URL,
                data=json.dumps(slack_payload),
                headers={'Content-Type': 'application/json; charset=utf-8'},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            print(f"Sent feature '{feature['title']}' to Slack.")
        except Exception as e:
            print(f"Failed to send Slack notification for '{feature['title']}': {e}", file=sys.stderr)


def check_for_updates() -> None:
    current_content = fetch_page_content()

    with shelve.open(STORAGE_FILE) as db:
        last_content = db.get("last_content", {})

        if current_content["Features"] != last_content.get("Features", []):
            print(f"Changes detected: {len(current_content['Features'])} features.")
            send_to_slack(current_content["Features"])
            db["last_content"] = current_content
        else:
            print("No changes detected.")


def main() -> None:
    print("Starting Chrome Enterprise release note monitor...")
    while True:
        try:
            check_for_updates()
        except Exception as e:
            print(f"Error during check: {e}", file=sys.stderr)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
