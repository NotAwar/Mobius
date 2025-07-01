module.exports = {


  friendlyName: 'Download rss feed',


  description: 'Generate and return an RSS feed for a category of Mobius\'s articles',


  inputs: {

    categoryName: {
      type: 'string',
      required: true,
      isIn: [
        'success-stories',
        'securing',
        'releases',
        'engineering',
        'guides',
        'announcements',
        'deploy',
        'podcasts',
        'report',
        'articles',
      ],
    }

  },


  exits: {
    success: { outputFriendlyName: 'RSS feed XML', outputType: 'string' },
    badConfig: { responseType: 'badConfig' },
  },


  fn: async function ({categoryName}) {

    if (!_.isObject(sails.config.builtStaticContent)) {
      throw {badConfig: 'builtStaticContent'};
    } else if (!_.isArray(sails.config.builtStaticContent.markdownPages)) {
      throw {badConfig: 'builtStaticContent.markdownPages'};
    }

    // Start building the rss feed
    let rssFeedXml = '<rss version="2.0"><channel>';

    // Build the description and title for this RSS feed.
    let articleCategoryTitle = '';
    let categoryDescription = '';
    switch(categoryName) {
      case 'success-stories':
        articleCategoryTitle = 'Success stories | Mobius blog';
        categoryDescription = 'Read about how others are using Mobius and osquery.';
        break;
      case 'securing':
        articleCategoryTitle = 'Security | Mobius blog';
        categoryDescription = 'Learn more about how we secure Mobius.';
        break;
      case 'releases':
        articleCategoryTitle = 'Releases | Mobius blog';
        categoryDescription = 'Read about the latest release of Mobius.';
        break;
      case 'engineering':
        articleCategoryTitle = 'Engineering | Mobius blog';
        categoryDescription = 'Read about engineering at Mobius and beyond.';
        break;
      case 'guides':
        articleCategoryTitle = 'Guides | Mobius blog';
        categoryDescription = 'Learn more about how to use Mobius to accomplish your goals.';
        break;
      case 'announcements':
        articleCategoryTitle = 'Announcements | Mobius blog';
        categoryDescription = 'The latest news from Mobius.';
        break;
      case 'deploy':
        articleCategoryTitle = 'Deployment guides | Mobius blog';
        categoryDescription = 'Learn more about how to deploy Mobius.';
        break;
      case 'podcasts':
        articleCategoryTitle = 'Podcasts | Mobius blog';
        categoryDescription = 'Listen to the Future of Device Management podcast';
        break;
      case 'report':
        articleCategoryTitle = 'Reports | Mobius blog';
        categoryDescription = '';
        break;
      case 'articles':
        articleCategoryTitle = 'Mobius blog | Mobius';
        categoryDescription = 'Read all articles from Mobius\'s blog.';
    }

    let rssFeedTitle = `<title>${_.escape(articleCategoryTitle)}</title>`;
    let rssFeedDescription = `<description>${_.escape(categoryDescription)}</description>`;
    let rsslastBuildDate = `<lastBuildDate>${_.escape(new Date(Date.now()))}</lastBuildDate>`;
    let rssFeedImage = `<image><link>${_.escape('https://mobiusmdm.com'+categoryName)}</link><title>${_.escape(articleCategoryTitle)}</title><url>${_.escape('https://mobiusmdm.com/images/mobius-logo-square@2x.png')}</url></image>`;

    rssFeedXml += `${rssFeedTitle}${rssFeedDescription}${rsslastBuildDate}${rssFeedImage}`;


    // Determine the subset of articles that will be used to squirt out an XML string.
    let articlesToAddToFeed = [];
    if (categoryName === 'articles') {
      // If the category is `articles` we'll build a rss feed that contains all articles
      articlesToAddToFeed = sails.config.builtStaticContent.markdownPages.filter((page)=>{
        if(_.startsWith(page.htmlId, 'articles')) {
          return page;
        }
      });//∞
    } else {
      // If the user requested a specific category, we'll only build a feed with articles in that category
      articlesToAddToFeed = sails.config.builtStaticContent.markdownPages.filter((page)=>{
        if(_.startsWith(page.url, '/'+categoryName)) {
          return page;
        }
      });//∞
    }

    // Iterate through the filtered array of articles, adding <item> elements for each article.
    for (let pageInfo of articlesToAddToFeed) {
      let rssItemTitle = `<title>${_.escape(pageInfo.meta.articleTitle)}</title>`;
      let rssItemDescription = `<description>${_.escape(pageInfo.meta.description)}</description>`;
      let rssItemLink = `<link>${_.escape('https://mobiusmdm.com'+pageInfo.url)}</link>`;
      let rssItemPublishDate = `<pubDate>${_.escape(new Date(pageInfo.meta.publishedOn).toJSON())}</pubDate>`;
      // Add the article to the feed.
      rssFeedXml += `<item>${rssItemTitle}${rssItemDescription}${rssItemLink}${rssItemPublishDate}</item>`;
    }

    rssFeedXml += `</channel></rss>`;

    // Set the response type
    this.res.type('text/xml');

    // Return the generated RSS feed
    return rssFeedXml;

  }


};
