<?php

declare(strict_types=1);

/**
 * Micro
 *
 * @copyright   Copryright (c) 2015-2018 gyselroth GmbH (https://gyselroth.com)
 * @license     MIT https://opensource.org/licenses/MIT
 */

namespace Micro\Auth;

use Closure;
use Psr\Log\LoggerInterface;

class AttributeMap implements AttributeMapInterface
{
    /**
     * Attribute map.
     *
     * @var iterable
     */
    protected $map = [];

    /**
     * Logger.
     *
     * @var Logger
     */
    protected $logger;

    /**
     * Custom mapper.
     *
     * @var array
     */
    protected $mapper = [];

    /**
     * Initialize.
     *
     * @param Logger $logger
     */
    public function __construct(Iterable $map, LoggerInterface $logger)
    {
        $this->logger = $logger;
        $this->map = $map;
    }

    /**
     * {@inheritdoc}
     */
    public function getAttributeMap(): Iterable
    {
        return $this->map;
    }

    /**
     * {@inheritdoc}
     */
    public function addMapper(string $type, Closure $closure): AttributeMapInterface
    {
        $this->mapper[$type] = $closure;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function map(array $data): array
    {
        $attrs = [];
        foreach ($this->map as $attr => $value) {
            if (isset($data[$value['attr']])) {
                $this->logger->info('found attribute mapping ['.$attr.'] => [('.$value['type'].') '.$value['attr'].']', [
                    'category' => get_class($this),
                ]);

                if ('array' === $value['type']) {
                    $store = $data[$value['attr']];
                } else {
                    $store = $data[$value['attr']];
                    if (is_array($store)) {
                        $store = array_shift($store);
                    }
                }

                if (isset($this->mapper[$value['type']])) {
                    $attrs[$attr] = $this->mapper[$value['type']]->call($this, $store);
                }

                switch ($value['type']) {
                    case 'array':
                        $arr = (array) $data[$value['attr']];
                        unset($arr['count']);
                        $attrs[$attr] = $arr;

                    break;
                    case 'string':
                         $attrs[$attr] = (string) $store;

                    break;
                    case 'int':
                         $attrs[$attr] = (int) $store;

                    break;
                    case 'bool':
                         $attrs[$attr] = (bool) $store;

                    break;
                    default:
                        $this->logger->error('unknown attribute type ['.$value['type'].'] for attribute ['.$attr.']; use one of [array,string,int,bool]', [
                            'category' => get_class($this),
                        ]);

                    break;
                }
            } else {
                $this->logger->warning('auth attribute ['.$value['attr'].'] was not found from authentication adapter response', [
                    'category' => get_class($this),
                ]);
            }
        }

        return $attrs;
    }
}
