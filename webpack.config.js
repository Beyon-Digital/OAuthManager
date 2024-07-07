const path = require("path");

module.exports = {
	entry: "./src/index.js",
	mode: "production", // 'development' or 'production'
	output: {
		path: path.resolve(__dirname, "dist"),
		filename: "index.js",
	},
	resolve: {
		extensions: [".ts", ".tsx", ".js"], // Add '.tsx' if you're using React
	},
	module: {
		rules: [
			{
				test: /\.tsx?$/, // This will match both '.ts' and '.tsx' files
				exclude: /node_modules/,
				use: {
					loader: "ts-loader",
				},
			},
			// Add other loaders here (e.g., for CSS, images, etc.)
		],
	},
};
