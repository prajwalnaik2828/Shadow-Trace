import re
from collections import Counter
import sys

def analyze_html(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    print(f"--- Analysis for {filepath} ---")
    
    # 1. Missing closing tags? Checked.
    
    # 2. aria attributes without proper roles?
    
    # 3. label tags without 'for' attribute
    labels = re.findall(r'<label([^>]*)>', content)
    missing_for = [l for l in labels if 'for=' not in l]
    print(f"Labels missing 'for': {len(missing_for)}")
    
    # 4. Duplicate classes
    # e.g. class="foo foo"
    class_attrs = re.findall(r'class=["\']([^"\']+)["\']', content)
    duplicate_classes = 0
    for cls in class_attrs:
        classes = cls.split()
        if len(classes) != len(set(classes)):
            duplicate_classes += 1
    print(f"Duplicate classes in class attributes: {duplicate_classes}")

    # 5. Empty elements like <div></div>
    empty_divs = re.findall(r'<div></div>', content)
    print(f"Empty divs: {len(empty_divs)}")
    
    # 6. inline onclick with HTML entities
    entities_in_onclick = re.findall(r'onclick=["\'][^"\']*&[a-z]+;[^"\']*["\']', content)
    print(f"Entities in onclick: {len(entities_in_onclick)}")
    
    # 7. <svg> without viewBox or similar?
    
    # 8. Unescaped < or > in text nodes
    # Let's check for <br> without / or something?
    brs = re.findall(r'<br>', content)
    print(f"<br> tags: {len(brs)}")

analyze_html('UIUX/settings.html')
analyze_html('UIUX/user_profile.html')
