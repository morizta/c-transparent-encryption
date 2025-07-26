#!/bin/bash

echo "Fixing Go PATH to use Go 1.21.5..."

# Remove old Go PATH entries
sed -i '/export PATH.*\/usr\/local\/go\/bin/d' ~/.bashrc

# Add new Go PATH at the beginning
echo '' >> ~/.bashrc
echo '# Go 1.21.5 - prioritize over system Go' >> ~/.bashrc
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc

echo "PATH updated in ~/.bashrc"
echo ""
echo "To use the new Go in your current terminal:"
echo "  source ~/.bashrc"
echo "  hash -r"
echo "  go version"
echo ""
echo "Or start a new terminal session."

# Test in a new bash session
echo "Testing in new shell session:"
bash -l -c 'go version'