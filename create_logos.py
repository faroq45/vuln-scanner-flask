#!/usr/bin/env python3
"""
Create VulScanner logo images using Python
Requires: pip install pillow
"""

try:
    from PIL import Image, ImageDraw, ImageFont
    import os
    
    def create_vulscanner_logo():
        """Create VulScanner logo images"""
        print("🎨 Creating VulScanner Logo Images...")
        
        # Logo dimensions
        width, height = 300, 120
        
        # Create white background logo (for sidebar)
        img_white = Image.new('RGB', (width, height), color='white')
        draw_white = ImageDraw.Draw(img_white)
        
        # Try to use a bold font, fallback to default
        try:
            font = ImageFont.truetype("arialbd.ttf", 24)  # Windows Arial Bold
        except:
            try:
                font = ImageFont.truetype("arial.ttf", 24)  # Windows Arial
            except:
                font = ImageFont.load_default()  # Default font
        
        # Calculate text position for centering
        text = "VulScanner"
        bbox = draw_white.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (width - text_width) // 2
        y = (height - text_height) // 2
        
        # Draw border
        draw_white.rectangle([5, 5, width-5, height-5], outline='black', width=2)
        
        # Draw text
        draw_white.text((x, y), text, fill='black', font=font)
        
        # Save white background logo
        logo_path = 'static/img/vulscanner_logo.png'
        img_white.save(logo_path)
        print(f"✅ Created: {logo_path}")
        
        # Create black background logo (for login)
        img_black = Image.new('RGB', (width, height), color='black')
        draw_black = ImageDraw.Draw(img_black)
        
        # Draw border
        draw_black.rectangle([5, 5, width-5, height-5], outline='white', width=2)
        
        # Draw text
        draw_black.text((x, y), text, fill='white', font=font)
        
        # Save black background logo
        logo_black_path = 'static/img/vulscanner_logo_black.png'
        img_black.save(logo_black_path)
        print(f"✅ Created: {logo_black_path}")
        
        print("\n🎉 VulScanner logos created successfully!")
        print("📁 Files created:")
        print(f"  • {logo_path}")
        print(f"  • {logo_black_path}")
        print("\n🔄 Restart your VulScanner to see the new logos!")
        
        return True
        
    if __name__ == "__main__":
        if not os.path.exists('static/img'):
            print("❌ Error: static/img directory not found!")
            print("Make sure you're running this script from the VulScanner root directory")
        else:
            create_vulscanner_logo()
            
except ImportError:
    print("❌ Pillow library not installed!")
    print("📦 Install it with: pip install pillow")
    print("📋 Then run this script again")
except Exception as e:
    print(f"❌ Error creating logos: {e}")
    print("\n💡 Alternative options:")
    print("1. Use the HTML logo generator (create_vulscanner_logo.html)")
    print("2. Use any image editor to create new logos with 'VulScanner' text")
    print("3. Use online text-to-image generators")