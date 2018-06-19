<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth\Middleware;

use Micro\Auth\Auth as CoreAuth;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class Auth implements MiddlewareInterface
{
    /**
     * @var CoreAuth
     */
    protected $auth;
    /**
     * @var string Attribute name for identity
     */
    protected $attribute = 'identity';

    /**
     * Set the Dispatcher instance.
     */
    public function __construct(CoreAuth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Set the attribute name to store handler reference.
     */
    public function attribute(string $attribute): self
    {
        $this->attribute = $attribute;

        return $this;
    }

    /**
     * Process a server request and return a response.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if ($identity = $this->auth->requireOne($request)) {
            $request = $this->setHandler($request, $identity);
        }
        //response 403

        return $handler->handle($request);
        /*$route = $this->router->dispatch($request->getMethod(), $request->getUri()->getPath());
        if ($route[0] === Dispatcher::NOT_FOUND) {
            return Factory::createResponse(404);
        }
        if ($route[0] === Dispatcher::METHOD_NOT_ALLOWED) {
            return Factory::createResponse(405)->withHeader('Allow', implode(', ', $route[1]));
        }
        foreach ($route[2] as $name => $value) {
            $request = $request->withAttribute($name, $value);
        }
        */

        //$request = $this->setHandler($request, $route[1]);
        //return $handler->handle($request);
    }

    /**
     * Set the handler reference on the request.
     */
    protected function setHandler(ServerRequestInterface $request, $handler): ServerRequestInterface
    {
        return $request->withAttribute($this->attribute, $handler);
    }
}
